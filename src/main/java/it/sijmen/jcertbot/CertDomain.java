package it.sijmen.jcertbot;

import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Certificate;
import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeRetryAfterException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import spark.Spark;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import static it.sijmen.jcertbot.JCertBot.newKeyPair;

class CertDomain {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertDomain.class);
    private final CertAccount account;

    private Path dir;
    private String domainName;
    private String organisation;

    private char[] keystorePassword;

    CertDomain(CertAccount account, String domainName, String organisation, char[] keystorePassword) throws IOException {
        this.account = account;
        this.dir = account.getDomainFolder(domainName);
        this.domainName = domainName;
        this.organisation = organisation;
        this.keystorePassword = keystorePassword;

        Files.createDirectories(dir);
    }

    boolean isValid() throws IOException {
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.MONTH, 1);
        cal.getTime();
        try {
            loadCertificate().checkValidity(cal.getTime());
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    void requestCertificate(String acmeUrl) throws IOException {
        Registration registration = account.getRegistration(acmeUrl);

        LOGGER.info("Requesting new certificate for domain name {}.", this.domainName);

        LOGGER.debug("Building certificate signing request...");
        CSRBuilder csrb = new CSRBuilder();
        csrb.addDomain(getDomainName());
        csrb.setOrganization(getOrganisation());
        csrb.sign(getDomainKeyPair());
        byte[] csr = csrb.getEncoded();
        LOGGER.debug("Building certificate signing request done.");

        doChallenge(registration, getDomainName());

        Certificate requestCertificate;
        try {
            LOGGER.debug("Requesting certificate...");
            requestCertificate = registration.requestCertificate(csr);
        } catch (AcmeException e) {
            throw new IOException(e);
        }
        LOGGER.debug("Writing certificate siging request to file");
        try (FileWriter fw = new FileWriter(getLastCsr().toFile())) {
            csrb.write(fw);
        }
        X509Certificate certificate = downloadCertificate(requestCertificate);
        storeCertificate(certificate);

        LOGGER.info("Requesting new certificate finished successfully. Certificate stored in {}.",
                getCertificateJks().toAbsolutePath().toString());
    }

    private X509Certificate loadCertificate() throws IOException {
        try (FileInputStream bos = new FileInputStream(getCertificateJks().toFile())) {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(bos, keystorePassword);
            return (X509Certificate) ks.getCertificate(domainName);
        }catch (Exception e){
            throw new IOException(e);
        }

    }

    private X509Certificate downloadCertificate(Certificate certificate) throws IOException {
        LOGGER.debug("Downloading certificate...");
        for(int i =0; i < 20; i++) {
            try {
                X509Certificate download = certificate.download();
                LOGGER.debug("Downloading certificate finished");
                return download;
            } catch (Exception e) {
                LOGGER.debug("Downloading certificate failed. Retrying in 3 seconds...", e);
            }
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                LOGGER.debug("Timeout between downloading certificate retry interrupted.", e);
            }
        }
        throw new IOException("Downloading certificate failed.");
    }

    private void storeCertificate(X509Certificate certificate) throws IOException {
        LOGGER.debug("Storing certificate in file {}", getCertificateJks().toAbsolutePath().toString());
        try (FileOutputStream bos = new FileOutputStream(getCertificateJks().toFile())) {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null);
            ks.setCertificateEntry(domainName, certificate);
            ks.store(bos, keystorePassword);
            bos.close();
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    private void doChallenge(Registration registration, String domain) throws IOException {
        Authorization authorization;
        try {
            LOGGER.info("Authorizing domain {}", domain);
            authorization = registration.authorizeDomain(domain);
        } catch (AcmeException e) {
            throw new IOException(e);
        }
        LOGGER.debug("Finding challenge for authorization.");
        Http01Challenge challenge = authorization.findChallenge(Http01Challenge.TYPE);

        String challengeToken = challenge.getToken();
        String challengeContent = challenge.getAuthorization();

        String url = "/.well-known/acme-challenge/"+challengeToken;
        LOGGER.debug("Setting up http challenge for domain {} on url {}.", domain, url);

        Spark.port(80);
        Spark.get(url, (req, res) -> {
            res.type("text/plain");
            return challengeContent;
        });

        try {
            LOGGER.debug("Triggering challenge.");
            challenge.trigger();
        } catch (AcmeException e) {
            throw new IOException(e);
        }

        waitforChallengeComplete(challenge);
        Spark.stop();

        LOGGER.info("Authorizing domain finished successfully.");
    }

    private void waitforChallengeComplete(Http01Challenge challenge) throws IOException {
        LOGGER.debug("Waiting for challenge completion.");
        int tries = 20;
        long sleep = 3000L;
        while (challenge.getStatus() != Status.VALID) {
            try {
                LOGGER.warn("Challenge update {}/{}.", 20-tries, 20);
                challenge.update();
            } catch (AcmeRetryAfterException e){
                sleep = e.getRetryAfter().toEpochMilli() - System.currentTimeMillis();
            } catch (AcmeException e) {
                LOGGER.warn("Challenge update failed with unknown error.", e);
            }
            tries--;

            if(challenge.getStatus() == Status.INVALID || tries == 0)
                throw new IOException("Challenge failed. Status: " + challenge.getStatus()
                        + " error: " + challenge.getError());
            try {
                Thread.sleep(sleep);
            } catch (InterruptedException e) {
                LOGGER.warn("Could not sleep between checking for challenge result", e);
            }
        }

        if(challenge.getStatus() != Status.VALID){
            throw new IOException("Challenge failed. Status: " + challenge.getStatus()
                    + " error: " + challenge.getError());
        }
    }

    private KeyPair getDomainKeyPair() throws IOException {
        File domainKeypairStore = getKeystore().toFile();
        if(domainKeypairStore.exists())
            return KeyPairUtils.readKeyPair(new FileReader(domainKeypairStore));
        else {
            LOGGER.debug("domainKeypair keypair file not found in {}. Generating a new one", domainKeypairStore.getAbsoluteFile());
            return newKeyPair("domainName", domainKeypairStore);
        }
    }

    private Path getKeystore(){
        return dir.resolve("domain-keystore.pem");
    }

    private Path getLastCsr(){
        return dir.resolve("last-csr-keystore.pem");
    }

    private Path getCertificateJks(){
        return dir.resolve("certificate.jks");
    }

    private String getDomainName() {
        return domainName;
    }

    private String getOrganisation() {
        return organisation;
    }
}
