package rotasaude.signer.engine;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.repository.CRLRepository;

/**
 * Repositório de LCR do Demoiselle (registrado por ServiceLoader). Todo download de LCR do
 * signer, o nosso e o do checker do Demoiselle, passa pelo CrlFetcher: política de destino,
 * cache e saúde da revogação. O App configura a política do ambiente na partida.
 */
public final class TrackingCrlRepository implements CRLRepository {

    private static volatile CrlFetcher fetcher = new CrlFetcher(
            new CrlUrlPolicy(false, CrlUrlPolicy::resolve), Clock.systemUTC(), maxAgeFromProperty(), timeoutFromEnv());

    public static void configure(CrlFetcher configured) {
        fetcher = configured;
    }

    public static Instant lastSuccess() {
        return RevocationHealth.lastSuccess();
    }

    /** Idade máxima do cache: signer.crlCacheMaxSeconds ou SIGNER_CRL_CACHE_MAX_SECONDS (padrão 3600). */
    public static Duration maxAgeFromProperty() {
        String raw = System.getProperty("signer.crlCacheMaxSeconds",
                System.getenv().getOrDefault("SIGNER_CRL_CACHE_MAX_SECONDS", "3600"));
        try {
            return Duration.ofSeconds(Math.max(0, Long.parseLong(raw.trim())));
        } catch (NumberFormatException e) {
            return Duration.ofHours(1);
        }
    }

    /** Timeout de conexão e leitura da LCR: SIGNER_CRL_CONNECTION_TIMEOUT em ms (padrão 5000). */
    public static int timeoutFromEnv() {
        try {
            return Integer.parseInt(System.getenv().getOrDefault("SIGNER_CRL_CONNECTION_TIMEOUT", "5000").trim());
        } catch (NumberFormatException e) {
            return 5000;
        }
    }

    @Override
    public Collection<ICPBR_CRL> getX509CRL(X509Certificate certificate) {
        return fetcher.fetch(certificate);
    }
}
