package rotasaude.signer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

class ConfigTest {

    private static final String TOKEN = "t".repeat(32);

    @Test
    void defaultsToPort8090() {
        Config config = Config.fromEnv(Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "development"), null);
        assertEquals(8090, config.port());
        assertFalse(config.toString().contains(TOKEN));
    }

    @Test
    void refusesMissingOrShortToken() {
        assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(Map.of("SIGNER_ENV", "development"), null));
        assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(Map.of("SIGNER_TOKEN", "t".repeat(31), "SIGNER_ENV", "development"), null));
    }

    @Test
    void refusesMissingEmptyOrUnknownEnvironment() {
        for (Map<String, String> env : new Map[] {
                Map.of("SIGNER_TOKEN", TOKEN),
                Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_ENV", ""),
                Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "   "),
                Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "prod"),
                Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "Production"),
                Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "test")}) {
            IllegalArgumentException refused = assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(env, null), env.toString());
            assertFalse(refused.getMessage().contains(TOKEN));
        }
    }

    @Test
    void refusesTestAnchorsAndDevPkiInProduction() {
        assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(Map.of(
                "SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "production", "SIGNER_EXTRA_TRUST_ANCHORS", "/x/anchors.pem"), null));
        assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(Map.of(
                "SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "production", "SIGNER_DEV_PKI_DIR", "/dev-pki"), null));
    }

    @Test
    void refusesTheExtraAnchorsSystemPropertyInProduction() {
        assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(Map.of(
                "SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "production"), "/x/anchors.pem"));
        assertEquals("production", Config.fromEnv(Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "production"), "  ").environment());
        assertEquals("production", Config.fromEnv(Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "production"), null).environment());
    }

    @Test
    void developmentAndStagingAcceptTheDevPki() {
        for (String environment : new String[] {"development", "staging"}) {
            Config config = Config.fromEnv(Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_ENV", environment,
                    "SIGNER_DEV_PKI_DIR", "/dev-pki", "SIGNER_EXTRA_TRUST_ANCHORS", "/dev-pki/anchors.pem"), "/dev-pki/anchors.pem");
            assertEquals("/dev-pki", config.devPkiDir());
            assertEquals("/dev-pki/anchors.pem", config.extraTrustAnchors());
            assertEquals(environment, config.environment());
        }
    }
}
