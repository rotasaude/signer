package rotasaude.signer;

import java.util.Map;
import rotasaude.signer.trust.ConfiguredAnchorsProviderCA;

/**
 * Configuração por ambiente. SIGNER_ENV é a mesma variável que o Demoiselle lê
 * (production desliga as cadeias de homologação); aqui ela também proíbe AC de teste.
 */
public record Config(String token, int port, String environment, String extraTrustAnchors, String devPkiDir, String version) {

    public static final int DEFAULT_PORT = 8090;
    public static final int MIN_TOKEN_LENGTH = 32;

    public static Config fromEnv(Map<String, String> env) {
        String token = env.get("SIGNER_TOKEN");
        if (token == null || token.length() < MIN_TOKEN_LENGTH) {
            throw new IllegalArgumentException("SIGNER_TOKEN ausente ou com menos de " + MIN_TOKEN_LENGTH + " caracteres");
        }
        int port = DEFAULT_PORT;
        String rawPort = env.get("SIGNER_PORT");
        if (rawPort != null && !rawPort.isBlank()) {
            try {
                port = Integer.parseInt(rawPort.trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("SIGNER_PORT inválida");
            }
        }
        String environment = env.getOrDefault("SIGNER_ENV", "").trim();
        String extra = blankToNull(env.get(ConfiguredAnchorsProviderCA.ENV));
        String devPki = blankToNull(env.get("SIGNER_DEV_PKI_DIR"));
        boolean production = "production".equalsIgnoreCase(environment) || "prod".equalsIgnoreCase(environment);
        if (production && (extra != null || devPki != null)) {
            throw new IllegalArgumentException("SIGNER_EXTRA_TRUST_ANCHORS e SIGNER_DEV_PKI_DIR são proibidos com SIGNER_ENV=production");
        }
        String version = Config.class.getPackage().getImplementationVersion();
        return new Config(token, port, environment, extra, devPki, version == null ? "dev" : version);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    @Override
    public String toString() {
        return "Config[port=" + port + ", environment=" + environment + "]"; // nunca o token
    }
}
