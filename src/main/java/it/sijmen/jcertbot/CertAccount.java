package it.sijmen.jcertbot;

import org.shredzone.acme4j.Registration;
import org.shredzone.acme4j.RegistrationBuilder;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.exception.AcmeConflictException;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.security.KeyPair;
import java.util.List;

import static it.sijmen.jcertbot.JCertBot.newKeyPair;

class CertAccount {

    private static final Logger LOGGER = LoggerFactory.getLogger(JCertBot.class);

    private Path base;
    private String contactEmail;

    CertAccount(Path base, String contactEmail) {
        this.base = base;
        this.contactEmail = contactEmail;
    }

    Registration getRegistration(String acmeUrl) throws IOException {
        LOGGER.debug("Opening session to {}", acmeUrl);
        Session session = new Session(acmeUrl, getAccountKeyPair());

        String storedRegistration = getStoredRegistration();
        if(storedRegistration != null) {
            LOGGER.debug("Using stored registration.");
            try {
                return Registration.bind(session, new URI(storedRegistration));
            } catch (URISyntaxException e) {
                LOGGER.error("Could not bind existing registration location to current session.", e);
                throw new IOException(e);
            }
        }else{
            LOGGER.debug("No existing registration found.");
            Registration registration = newRegistration(session);
            storeRegistration(registration);
            return registration;
        }
    }

    Path getDomainFolder(String domain) {
        return base.resolve(domain);
    }

    private Registration newRegistration(Session session) throws IOException {
        try {
            RegistrationBuilder registrationBuilder = new RegistrationBuilder();
            registrationBuilder.addContact("mailto:"+contactEmail);
            LOGGER.debug("Registering new account...");
            Registration registration = registrationBuilder.create(session);
            LOGGER.debug("Agreeing to terms of service agreement...");
            registration.modify().setAgreement(registration.getAgreement()).commit();
            LOGGER.debug("Registration complete");
            return registration;
        } catch (AcmeConflictException ex) {
            return Registration.bind(session, ex.getLocation());
        } catch (AcmeException e) {
            throw new IOException(e);
        }
    }

    private String getStoredRegistration() throws IOException {
        Path registrationStore = getRegistrationStore();
        if(!Files.exists(registrationStore))
            return null;
        List<String> lines = Files.readAllLines(registrationStore);
        return lines.get(0);
    }

    private void storeRegistration(Registration registration) throws IOException {
        LOGGER.debug("Storing registration location in {}", getRegistrationStore().toAbsolutePath().toString());
        Files.write(getRegistrationStore(), registration.getLocation().toString().getBytes(),
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }

    private KeyPair getAccountKeyPair() throws IOException {
        Path accountKeystore = getAccountKeystore();
        if(Files.exists(accountKeystore))
            return KeyPairUtils.readKeyPair(new FileReader(accountKeystore.toFile()));
        else {
            LOGGER.debug("account keypair file not found in {}. Generating a new one.", accountKeystore.toAbsolutePath().toString());
            return newKeyPair("account", accountKeystore.toFile());
        }
    }

    private Path getAccountKeystore(){
        return base.resolve("account.pem");
    }

    private Path getRegistrationStore(){
        return base.resolve("registration.txt");
    }
}
