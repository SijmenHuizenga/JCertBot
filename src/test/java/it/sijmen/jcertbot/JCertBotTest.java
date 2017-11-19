package it.sijmen.jcertbot;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Paths;

public class JCertBotTest {

    /** To run this unit test add a domain name that points to your machine. */
    public static final String TESTDOMAINNAME = "localhost.sijmen.it";

    @Test
    public void testGetCertificate() throws IOException {
        org.apache.log4j.BasicConfigurator.configure();

        Logger logger = Logger.getLogger("org");
        logger.setLevel(Level.OFF);

        logger = Logger.getLogger("spark");
        logger.setLevel(Level.OFF);

        JCertBot bot = new JCertBot(Paths.get("./jcertbot"), "info@example.com");

        bot.refreshCertificate(TESTDOMAINNAME, true, "JCertBot", "password".toCharArray(), false, true);
    }

}
