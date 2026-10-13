package rotasaude.signer;

import java.util.Map;
import java.util.Set;
import rotasaude.signer.trust.ConfiguredAnchorsProviderCA;

/**
 * Configuração por ambiente. SIGNER_ENV é obrigatória e vale development, staging ou production
 * (exatamente assim, minúsculas). É a mesma variável que o Demoiselle lê: production desliga as
 * cadeias de homologação da ICP-Brasil. Aqui production também proíbe AC de teste, por variável
 * (SIGNER_EXTRA_TRUST_ANCHORS, SIGNER_DEV_PKI_DIR) ou pela propriedade signer.extraTrustAnchors
 * (alcançável por JAVA_TOOL_OPTIONS). Sem SIGNER_ENV válida o boot falha: a guarda não é opcional.
 */
public record Config(String token, int port, String environment, String extraTrustAnchors, String devPkiDir, String version,
                     int maxConcurrency) {

    public static final int DEFAULT_PORT = 8090;
    /** Operações simultâneas (prepare/assemble/verify/check); o excesso recebe 503 busy. */
    public static final int DEFAULT_MAX_CONCURRENCY = 8;
    public static final int MIN_TOKEN_LENGTH = 32;
    public static final Set<String> ENVIRONMENTS = Set.of("development", "staging", "production");

    public static Config fromEnv(Map<String, String> env) {
        return fromEnv(env, System.getProperty(ConfiguredAnchorsProviderCA.PROPERTY));
    }

    /** extraAnchorsProperty: valor da propriedade signer.extraTrustAnchors (injetado para teste). */
    static Config fromEnv(Map<String, String> env, String extraAnchorsProperty) {
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
        String environment = env.get("SIGNER_ENV");
        if (environment == null || !ENVIRONMENTS.contains(environment)) {
            throw new IllegalArgumentException("SIGNER_ENV ausente ou inválida (use development, staging ou production)");
        }
        String extra = blankToNull(env.get(ConfiguredAnchorsProviderCA.ENV));
        String devPki = blankToNull(env.get("SIGNER_DEV_PKI_DIR"));
        if ("production".equals(environment) && (extra != null || devPki != null || blankToNull(extraAnchorsProperty) != null)) {
            throw new IllegalArgumentException("SIGNER_EXTRA_TRUST_ANCHORS, SIGNER_DEV_PKI_DIR e -D"
                    + ConfiguredAnchorsProviderCA.PROPERTY + " são proibidos com SIGNER_ENV=production");
        }
        int maxConcurrency = DEFAULT_MAX_CONCURRENCY;
        String rawConcurrency = env.get("SIGNER_MAX_CONCURRENCY");
        if (rawConcurrency != null && !rawConcurrency.isBlank()) {
            try {
                maxConcurrency = Integer.parseInt(rawConcurrency.trim());
            } catch (NumberFormatException e) {
                maxConcurrency = 0;
            }
            if (maxConcurrency < 1) throw new IllegalArgumentException("SIGNER_MAX_CONCURRENCY inválida");
        }
        String version = Config.class.getPackage().getImplementationVersion();
        return new Config(token, port, environment, extra, devPki, version == null ? "dev" : version, maxConcurrency);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    @Override
    public String toString() {
        return "Config[port=" + port + ", environment=" + environment + "]"; // nunca o token
    }
}
