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
 * Saúde da revogação para o /health e para o log: último download bom, total de falhas e,
 * por host de LCR, o início da falha atual (o /health mostra a mais antiga). O log só traz o host da LCR (nunca DN, CPF ou nome)
 * e no máximo uma linha por host por minuto.
 */
public final class RevocationHealth {

    private static final Logger LOG = LogManager.getLogger(RevocationHealth.class);
    private static final Duration LOG_EVERY = Duration.ofMinutes(1);
    private static final AtomicReference<Instant> LAST_SUCCESS = new AtomicReference<>();
    /** Hosts de LCR em falha agora, com o início da falha de cada um. */
    private static final Map<String, Instant> FAILING_SINCE = new ConcurrentHashMap<>();
    private static final AtomicLong UNAVAILABLE = new AtomicLong();
    private static final Map<String, Instant> LOGGED = new ConcurrentHashMap<>();

    private RevocationHealth() {}

    public static void recordSuccess(String host, Instant at) {
        LAST_SUCCESS.set(at);
        FAILING_SINCE.remove(key(host));
    }

    public static void recordFailure(String host, Instant at) {
        UNAVAILABLE.incrementAndGet();
        String key = key(host);
        FAILING_SINCE.putIfAbsent(key, at);
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

    /** Início da queda mais antiga entre os hosts que seguem em falha (null = nenhum). */
    public static Instant unavailableSince() {
        return FAILING_SINCE.values().stream().min(Instant::compareTo).orElse(null);
    }

    private static String key(String host) {
        return host == null ? "?" : host;
    }

    /** Zera o controle de frequência do log (teste). */
    static void forgetLogs() {
        LOGGED.clear();
    }

    /** Esquece as falhas em curso (teste: o estado é estático e compartilhado na JVM). */
    static void forgetOutages() {
        FAILING_SINCE.clear();
    }
}
