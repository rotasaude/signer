package rotasaude.signer.engine;

import java.time.Instant;
import java.util.List;

/** Resultado do /verify (contrato §9). Campos do titular são null quando não há como lê-los. */
public record Verification(String status, String signerCpf, String signerName, String policyOid,
                           Instant signedAt, List<String> reasons) {

    public static final String VALID = "valid";
    public static final String INVALID = "invalid";
    public static final String INDETERMINATE = "indeterminate";

    static Verification malformed() {
        return new Verification(INVALID, null, null, null, null, List.of("malformed_signature"));
    }
}
