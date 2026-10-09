package rotasaude.signer.engine;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * O que o /prepare devolve e o /assemble recebe de volta (pelo prepared_state).
 * signedAttributesDer é exatamente o que o PSC assina (RAW = SHA256withRSA sobre esses bytes).
 * preparedPdf só existe em PAdES: o PDF com a assinatura reservada (zeros) e a data M gravada.
 */
public record PreparedSignature(Kind kind, byte[] certificateDer, byte[] signedAttributesDer, byte[] preparedPdf) {

    public byte[] toBeSignedSha256() {
        try {
            return MessageDigest.getInstance("SHA-256").digest(signedAttributesDer);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
