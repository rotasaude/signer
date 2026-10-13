package rotasaude.signer.engine;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Saúde da revogação para o /health e para o log: último download bom, total de falhas e
 * início da sequência de falhas atual. O log só traz o host da LCR (nunca DN, CPF ou nome)
 * e no máximo uma linha por host por minuto.
 */
public final class RevocationHealth {

    private static final Logger LOG = LogManager.getLogger(RevocationHealth.class);
    private static final Duration LOG_EVERY = Duration.ofMinutes(1);
    private static final AtomicReference<Instant> LAST_SUCCESS = new AtomicReference<>();
    private static final AtomicReference<Instant> UNAVAILABLE_SINCE = new AtomicReference<>();
    private static final AtomicLong UNAVAILABLE = new AtomicLong();
    private static final Map<String, Instant> LOGGED = new ConcurrentHashMap<>();

    private RevocationHealth() {}

    public static void recordSuccess(Instant at) {
        LAST_SUCCESS.set(at);
        UNAVAILABLE_SINCE.set(null);
    }

    public static void recordFailure(String host, Instant at) {
        UNAVAILABLE.incrementAndGet();
        UNAVAILABLE_SINCE.compareAndSet(null, at);
        String key = host == null ? "?" : host;
        Instant last = LOGGED.get(key);
        if (last == null || !at.isBefore(last.plus(LOG_EVERY))) {
            LOGGED.put(key, at);
            LOG.warn("revocation_unavailable host={}", key);
        }
    }

    public static Instant lastSuccess() {
        return LAST_SUCCESS.get();
    }

    public static long unavailableCount() {
        return UNAVAILABLE.get();
    }

    public static Instant unavailableSince() {
        return UNAVAILABLE_SINCE.get();
    }

    /** Zera o controle de frequência do log (teste). */
    static void forgetLogs() {
        LOGGED.clear();
    }
}
