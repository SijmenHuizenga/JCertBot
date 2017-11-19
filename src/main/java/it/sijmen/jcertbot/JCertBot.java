package it.sijmen.jcertbot;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.*;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;
import spark.Spark;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class JCertBot {

    private static final Logger LOGGER = LoggerFactory.getLogger(JCertBot.class);

    private CertAccount account;

    public JCertBot(Path directory, String contactEmail) {
        account = new CertAccount(directory, contactEmail);
    }

    public void refreshCertificate(String domainName, boolean acceptAgreement, String organisation,
                                   char[] keystorefile, boolean forceRequestNew, boolean useStaging) throws IOException {
        if(!acceptAgreement)
            throw new IOException("You must agree to the terms of service of Let's Encrypt. " +
                    "Read more here: https://letsencrypt.org/repository/)");

        CertDomain certDomain = new CertDomain(account, domainName, organisation, keystorefile);
        if(!forceRequestNew && certDomain.isValid()) {
            LOGGER.info("Existing certificate is still valid for at least another 30 days. Not requesting new certificate.");
            return;
        }

        certDomain.requestCertificate(useStaging ? "acme://letsencrypt.org/staging" : "acme://letsencrypt.org/v01");
    }

    static KeyPair newKeyPair(String name, File file) throws IOException {
        LOGGER.debug("Generating new "+name+" 4096 bit keypair");
        KeyPair keyPair = KeyPairUtils.createKeyPair(4096);

        LOGGER.debug("Writing new "+name+" keyfile to {}", file.getAbsoluteFile());
        KeyPairUtils.writeKeyPair(keyPair, new FileWriter(file));

        return keyPair;
    }

}
