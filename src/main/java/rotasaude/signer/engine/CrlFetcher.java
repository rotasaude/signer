package rotasaude.signer.engine;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.repository.ConfigurationRepo;

/**
 * Baixa as LCRs dos pontos de distribuição do certificado, só para destinos que a política
 * aceita, com cache por URL até o menor entre o nextUpdate e a idade máxima. LCR já vencida
 * não entra no cache (quem decide se ela vale é Revocation). Nunca lança: falha vira lista
 * vazia e conta em RevocationHealth.
 */
public final class CrlFetcher {

    static final int MAX_CRL_BYTES = 10 * 1024 * 1024;
    static final int MAX_ENTRIES = 256;

    private record Entry(ICPBR_CRL crl, Instant expires) {}

    private final CrlUrlPolicy policy;
    private final Clock clock;
    private final Duration maxAge;
    private final int timeoutMillis;
    private final Map<String, Entry> cache = new ConcurrentHashMap<>();

    public CrlFetcher(CrlUrlPolicy policy, Clock clock, Duration maxAge, int timeoutMillis) {
        this.policy = policy;
        this.clock = clock;
        this.maxAge = maxAge;
        this.timeoutMillis = timeoutMillis;
    }

    public List<ICPBR_CRL> fetch(X509Certificate certificate) {
        List<String> urls;
        try {
            urls = new BasicCertificate(certificate).getCRLDistributionPoint();
        } catch (Exception e) {
            urls = null;
        }
        List<ICPBR_CRL> crls = new ArrayList<>();
        if (urls == null) return crls;
        for (String url : urls) {
            ICPBR_CRL crl = one(url);
            if (crl != null) crls.add(crl);
        }
        return crls;
    }

    private ICPBR_CRL one(String url) {
        Instant now = clock.instant();
        String host = host(url);
        if (!policy.allowed(url)) {
            RevocationHealth.recordFailure(host, now);
            return null;
        }
        Entry cached = cache.get(url);
        if (cached != null && now.isBefore(cached.expires())) return cached.crl();
        try {
            ICPBR_CRL crl = new ICPBR_CRL(download(url));
            remember(url, crl, now);
            RevocationHealth.recordSuccess(now);
            return crl;
        } catch (Exception e) {
            cache.remove(url);
            RevocationHealth.recordFailure(host, now);
            return null;
        }
    }

    private void remember(String url, ICPBR_CRL crl, Instant now) {
        if (maxAge.isZero() || maxAge.isNegative() || crl.getCRL() == null || crl.getCRL().getNextUpdate() == null) return;
        Instant expires = now.plus(maxAge);
        Instant next = crl.getCRL().getNextUpdate().toInstant();
        if (next.isBefore(expires)) expires = next;
        if (!expires.isAfter(now)) return;
        if (cache.size() >= MAX_ENTRIES) cache.clear();
        cache.put(url, new Entry(crl, expires));
    }

    private byte[] download(String url) throws Exception {
        Proxy proxy = ConfigurationRepo.getInstance().getProxy();
        HttpURLConnection connection = (HttpURLConnection) (proxy == null
                ? URI.create(url).toURL().openConnection()
                : URI.create(url).toURL().openConnection(proxy));
        connection.setConnectTimeout(timeoutMillis);
        connection.setReadTimeout(timeoutMillis);
        connection.setInstanceFollowRedirects(false); // redirecionamento driblaria a política
        try {
            if (connection.getResponseCode() != 200) throw new IllegalStateException("status");
            try (InputStream in = connection.getInputStream()) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                byte[] buffer = new byte[8192];
                int total = 0;
                for (int read; (read = in.read(buffer)) != -1; ) {
                    total += read;
                    if (total > MAX_CRL_BYTES) throw new IllegalStateException("too large");
                    out.write(buffer, 0, read);
                }
                return out.toByteArray();
            }
        } finally {
            connection.disconnect();
        }
    }

    private static String host(String url) {
        try {
            return URI.create(url).getHost();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
