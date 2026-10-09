package rotasaude.signer.engine;

import java.util.Locale;
import rotasaude.signer.SignerFailure;

public enum Kind {
    CADES, PADES;

    public static Kind parse(Object value) {
        if ("cades".equals(value)) return CADES;
        if ("pades".equals(value)) return PADES;
        throw new SignerFailure(SignerFailure.Code.INVALID_REQUEST);
    }

    public String wire() {
        return name().toLowerCase(Locale.ROOT);
    }
}
