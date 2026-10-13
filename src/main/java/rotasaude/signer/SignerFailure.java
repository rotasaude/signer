package rotasaude.signer;

/**
 * Recusa com código do contrato (§9). A mensagem é o próprio código: nunca carrega
 * texto de exceção de terceiros (que pode trazer DN com nome e CPF do titular).
 */
public final class SignerFailure extends RuntimeException {

    public enum Code {
        INVALID_REQUEST(400, "invalid_request"),
        UNAUTHORIZED(401, "unauthorized"),
        INVALID_CERTIFICATE(422, "invalid_certificate"),
        INVALID_SIGNATURE_VALUE(422, "invalid_signature_value"),
        ASSEMBLED_SIGNATURE_INVALID(422, "assembled_signature_invalid"),
        INTERNAL(500, "internal"),
        BUSY(503, "busy");

        public final int status;
        public final String wire;

        Code(int status, String wire) {
            this.status = status;
            this.wire = wire;
        }
    }

    public final Code code;

    public SignerFailure(Code code) {
        super(code.wire, null, false, false);
        this.code = code;
    }
}
