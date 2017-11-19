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

    /**
     * @param directory The JCertBot storage location. This folder is used to store the generated certificates and
     *                  everything that is needed to issue new certificates. Make sure this folder is secure! All
     *                  information in this folder has confidential information that should only be accessed by
     *                  the application administrator.
     * @param contactEmail The contact email address that is used to send expiration email reminders for certificates 
     *                     issued with this account. This is all managed by Let's Encrypt. 
     */
    public JCertBot(Path directory, String contactEmail) {
        account = new CertAccount(directory, contactEmail);
    }

    /**
     * issue a new certificate for a single domain name. If there is already a certificate found in the
     * storage directory and this certificate is still valid for at least another 30 days, than no new certificate
     * is issued.
     *
     * Requesting a new certificate or refreshing an old certificate works as follows:
     * 1. If no previous account-registration is found in the JCertBot storage directory than a new account is key
     *    is generated and a new account is registered for Let's Encrypt.
     * 2. The domain name is verified using a http challenge. This opens a http server on port 80 to publish the
     *    challenge key.
     * 3. A new domain keypair is generated if not already present.
     * 4. A new certificate is requested and downloaded. The certificate is stored in a subfolder in the
     *    JCertBot storage directory with the domain name as subdirectory name.
     *
     * @param domainName The domain name for which to generate a new certificate.
     * @param acceptAgreement Weather or not you agree to the terms of service of Let's Encrypt. This argument must be
     *                        true if you want to use Let's Encrypt.
     * @param organisation The organisation name that is coupled to the generated certificate. This is a required
     *                     option by Let's Encrypt.
     * @param keystorePassword The password of the keystore where the certificate is stored in. This is the password
     *                         of the output .jsk file.
     * @param forceRequestNew Set this argument to true to force generate a new certificate and not check the validity
     *                        of any existing certificates.
     * @param useStaging If this argument is true, than the Let's Encrypt staging environment is used. This staging
     *                   environment should be used for testing purposes. Set this argument only to true in production.
     *                   The live environment of Let's Encrypt has restrictions on the amount of certificates that can be
     *                   generated. So use with care!
     * @throws IOException when the certificate creation fails. There are many reasons why certificate issuing might fail.
     *                     Before complaining please check if you have permission to bind to port 80 and if the ip that
     *                     is available through the dns of your domain name is accessible is referencing the machine that
     *                     you are running on.
     */
    public void refreshCertificate(String domainName, boolean acceptAgreement, String organisation,
                                   char[] keystorePassword, boolean forceRequestNew, boolean useStaging) throws IOException {
        if(!acceptAgreement)
            throw new IOException("You must agree to the terms of service of Let's Encrypt. " +
                    "Read more here: https://letsencrypt.org/repository/)");

        CertDomain certDomain = new CertDomain(account, domainName, organisation, keystorePassword);
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
