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
        Config config = Config.fromEnv(Map.of("SIGNER_TOKEN", TOKEN));
        assertEquals(8090, config.port());
        assertFalse(config.toString().contains(TOKEN));
    }

    @Test
    void refusesMissingOrShortToken() {
        assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(Map.of()));
        assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(Map.of("SIGNER_TOKEN", "t".repeat(31))));
    }

    @Test
    void refusesTestAnchorsAndDevPkiInProduction() {
        assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(Map.of(
                "SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "production", "SIGNER_EXTRA_TRUST_ANCHORS", "/x/anchors.pem")));
        assertThrows(IllegalArgumentException.class, () -> Config.fromEnv(Map.of(
                "SIGNER_TOKEN", TOKEN, "SIGNER_ENV", "prod", "SIGNER_DEV_PKI_DIR", "/dev-pki")));
        assertEquals("/dev-pki", Config.fromEnv(Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_DEV_PKI_DIR", "/dev-pki")).devPkiDir());
    }
}
