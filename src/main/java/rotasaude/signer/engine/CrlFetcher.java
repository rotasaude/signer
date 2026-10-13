package rotasaude.signer.engine;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.demoiselle.signer.core.ca.manager.CAManager;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.repository.ConfigurationRepo;

/**
 * Baixa as LCRs dos pontos de distribuição do certificado, só para destinos que a política
 * aceita, parando na primeira que responde, com cache por URL até o menor entre o nextUpdate e
 * a idade máxima. Só LCR que confere entra no cache (quem decide se ela vale é Revocation). Nunca lança: falha vira lista
 * vazia e conta em RevocationHealth.
 */
public final class CrlFetcher {

    static {
        // ICPBR_CRL lê a LCR pelo provedor "BC"; quem chegava aqui antes (o OnLineCRLRepository) o registrava.
        if (java.security.Security.getProvider("BC") == null) {
            java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        }
    }

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
        return fetch(certificate, urls == null ? List.of() : urls);
    }

    /** Para no primeiro ponto de distribuição que entrega uma LCR (como o OnLineCRLRepository). */
    List<ICPBR_CRL> fetch(X509Certificate certificate, List<String> urls) {
        List<ICPBR_CRL> crls = new ArrayList<>();
        for (String url : urls) {
            ICPBR_CRL crl = one(certificate, url);
            if (crl != null) {
                crls.add(crl);
                break;
            }
        }
        return crls;
    }

    private ICPBR_CRL one(X509Certificate certificate, String url) {
        Instant now = clock.instant();
        String host = host(url);
        if (!policy.allowed(url)) {
            RevocationHealth.recordFailure(host, now);
            return null;
        }
        Entry cached = cache.get(url);
        if (cached != null && now.isBefore(cached.expires())) {
            RevocationHealth.recordSuccess(host, now);
            return cached.crl();
        }
        try {
            ICPBR_CRL crl = new ICPBR_CRL(download(url));
            remember(url, certificate, crl, now);
            RevocationHealth.recordSuccess(host, now);
            return crl;
        } catch (Exception e) {
            cache.remove(url);
            RevocationHealth.recordFailure(host, now);
            return null;
        }
    }

    /**
     * Só guarda LCR que confere: emitente igual ao do certificado, assinada pela AC emissora e já
     * vigente. Uma resposta ruim (relógio da AC adiantado, LCR de outra AC) não fica presa no cache.
     */
    private void remember(String url, X509Certificate certificate, ICPBR_CRL crl, Instant now) {
        if (maxAge.isZero() || maxAge.isNegative()) return;
        X509CRL x509 = crl.getCRL();
        if (x509 == null || x509.getNextUpdate() == null || x509.getThisUpdate().toInstant().isAfter(now)) return;
        if (!x509.getIssuerX500Principal().equals(certificate.getIssuerX500Principal())) return;
        X509Certificate issuer = issuerOf(certificate);
        if (issuer == null) return;
        try {
            x509.verify(issuer.getPublicKey());
        } catch (Exception e) {
            return;
        }
        Instant expires = now.plus(maxAge);
        Instant next = x509.getNextUpdate().toInstant();
        if (next.isBefore(expires)) expires = next;
        if (!expires.isAfter(now)) return;
        if (cache.size() >= MAX_ENTRIES) cache.clear();
        cache.put(url, new Entry(crl, expires));
    }

    /** Emissor pelas âncoras locais (o mesmo CAManager do Chain); sem ele, não se guarda. */
    private static X509Certificate issuerOf(X509Certificate certificate) {
        try {
            List<X509Certificate> chain = List.copyOf(CAManager.getInstance().getCertificateChain(certificate));
            return chain.size() < 2 ? null : chain.get(1);
        } catch (RuntimeException e) {
            return null;
        }
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
