package rotasaude.signer.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Base64;
import org.junit.jupiter.api.Test;
import rotasaude.signer.SignerFailure;

class PreparedStateCodecTest {

    private static final String TOKEN = "a".repeat(40);
    private final PreparedStateCodec codec = new PreparedStateCodec(TOKEN);
    private final PreparedSignature cades = new PreparedSignature(Kind.CADES, new byte[] {1, 2, 3}, new byte[] {4, 5}, null);

    @Test
    void roundTrips() {
        PreparedSignature back = codec.decode(codec.encode(new PreparedSignature(Kind.PADES, new byte[] {1}, new byte[] {2}, new byte[] {3, 4})));
        assertEquals(Kind.PADES, back.kind());
        assertArrayEquals(new byte[] {1}, back.certificateDer());
        assertArrayEquals(new byte[] {2}, back.signedAttributesDer());
        assertArrayEquals(new byte[] {3, 4}, back.preparedPdf());
        assertNull(codec.decode(codec.encode(cades)).preparedPdf());
    }

    @Test
    void refusesATamperedState() {
        byte[] raw = Base64.getDecoder().decode(codec.encode(cades));
        raw[5] ^= 0x01;
        assertInvalid(Base64.getEncoder().encodeToString(raw));
    }

    @Test
    void refusesAStateSealedWithAnotherToken() {
        assertInvalid(new PreparedStateCodec("b".repeat(40)).encode(cades));
    }

    @Test
    void refusesGarbage() {
        assertInvalid("%%not-base64%%");
        assertInvalid(Base64.getEncoder().encodeToString(new byte[10]));
    }

    private void assertInvalid(String state) {
        SignerFailure failure = assertThrows(SignerFailure.class, () -> codec.decode(state));
        assertEquals(SignerFailure.Code.INVALID_REQUEST, failure.code);
    }
}
