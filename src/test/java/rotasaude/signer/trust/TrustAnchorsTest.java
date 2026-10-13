package rotasaude.signer.trust;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import rotasaude.signer.support.TestPki;

/** Partida sem âncora de confiança não sobe (R1, signer#1 item 4). */
class TrustAnchorsTest {

    @Test
    void countsTheConfiguredAnchors() {
        TestPki.get(); // a AC de teste entra pela propriedade signer.extraTrustAnchors
        assertTrue(TrustAnchors.count() > 0);
        assertDoesNotThrow(() -> TrustAnchors.requireAny());
    }

    @Test
    void noAnchorRefusesToBoot() {
        assertThrows(IllegalStateException.class, () -> TrustAnchors.requireAny(0));
    }
}
