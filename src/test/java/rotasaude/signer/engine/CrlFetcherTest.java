package rotasaude.signer.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import rotasaude.signer.support.TestPki;

/** Download de LCR do signer (R1, signer#1 itens 3, 6 e 9). */
class CrlFetcherTest {

    private static final TestPki PKI = TestPki.get();

    @AfterEach
    void back() {
        PKI.crlAvailable(true);
        PKI.crlMode(TestPki.CrlMode.GOOD);
    }

    private static CrlUrlPolicy local() {
        return new CrlUrlPolicy(false, host -> addresses("127.0.0.1"));
    }

    @Test
    void productionRefusesPrivateLoopbackAndLinkLocalTargets() {
        CrlUrlPolicy policy = new CrlUrlPolicy(true, host -> switch (host) {
            case "lcr.iti.gov.br" -> addresses("200.152.32.10");
            case "intranet" -> addresses("10.0.0.5");
            case "meta" -> addresses("169.254.169.254");
            case "ula" -> addresses("fd12::1");
            default -> addresses("127.0.0.1");
        });
        assertTrue(policy.allowed("http://lcr.iti.gov.br/ac.crl"));
        assertTrue(policy.allowed("https://lcr.iti.gov.br/ac.crl"));
        assertFalse(policy.allowed("http://intranet/ac.crl"));
        assertFalse(policy.allowed("http://meta/latest"));
        assertFalse(policy.allowed("http://ula/ac.crl"));
        assertFalse(policy.allowed("http://localhost:8080/ac.crl"));
        assertFalse(policy.allowed("ldap://lcr.iti.gov.br/cn=ac"));
        assertFalse(policy.allowed("file:///etc/passwd"));
        assertFalse(policy.allowed("not a url"));
    }

    @Test
    void developmentAllowsLocalhostButStillOnlyHttp() {
        assertTrue(local().allowed("http://127.0.0.1:9000/intermediate.crl"));
        assertFalse(local().allowed("ldap://127.0.0.1/cn=ac"));
    }

    @Test
    void productionPolicyRefusesTheLocalTestAuthorityAsUnavailableNotInvalid() throws Exception {
        CrlFetcher fetcher = new CrlFetcher(new CrlUrlPolicy(true, host -> addresses("127.0.0.1")), Clock.systemUTC(), Duration.ZERO, 2000);
        assertEquals(0, fetcher.fetch(PKI.professional().certificate()).size());
    }

    @Test
    void cachesUntilTheConfiguredAgeAndDownloadsAgainAfterIt() throws Exception {
        MutableClock clock = new MutableClock(Instant.now());
        CrlFetcher fetcher = new CrlFetcher(local(), clock, Duration.ofMinutes(10), 2000);
        X509Certificate certificate = PKI.professional().certificate();

        assertEquals(1, fetcher.fetch(certificate).size());
        PKI.crlAvailable(false);
        assertEquals(1, fetcher.fetch(certificate).size(), "dentro da validade do cache: não baixa de novo");
        clock.advance(Duration.ofMinutes(11));
        assertEquals(0, fetcher.fetch(certificate).size(), "venceu o cache: baixa, falha e não entrega a velha");
    }

    @Test
    void neverCachesAcrlPastItsNextUpdate() throws Exception {
        CrlFetcher fetcher = new CrlFetcher(local(), Clock.systemUTC(), Duration.ofDays(30), 2000);
        X509Certificate certificate = PKI.professional().certificate();
        PKI.crlMode(TestPki.CrlMode.EXPIRED); // nextUpdate já no passado
        assertEquals(1, fetcher.fetch(certificate).size());
        PKI.crlAvailable(false);
        assertEquals(0, fetcher.fetch(certificate).size(), "LCR vencida não fica no cache");
    }

    @Test
    void failuresAreCountedAndLoggedOncePerHostWithoutCertificateData() throws Exception {
        long before = RevocationHealth.unavailableCount();
        PKI.crlAvailable(false);
        CrlFetcher fetcher = new CrlFetcher(local(), Clock.systemUTC(), Duration.ZERO, 2000);
        X509Certificate certificate = PKI.professional().certificate();
        RevocationHealth.forgetLogs();

        PrintStream original = System.out;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            for (int i = 0; i < 3; i++) fetcher.fetch(certificate);
        } finally {
            System.setOut(original);
        }

        assertTrue(RevocationHealth.unavailableCount() >= before + 3);
        assertNotNull(RevocationHealth.unavailableSince());
        String log = captured.toString(StandardCharsets.UTF_8);
        assertEquals(1, log.split("revocation_unavailable host=127.0.0.1", -1).length - 1, log);
        assertFalse(log.contains(TestPki.CPF), log);
        assertFalse(log.contains(TestPki.NAME), log);

        PKI.crlAvailable(true);
        fetcher.fetch(certificate);
        assertEquals(null, RevocationHealth.unavailableSince(), "sucesso encerra a sequência de falhas");
    }

    private static InetAddress[] addresses(String ip) {
        try {
            return new InetAddress[] {InetAddress.getByName(ip)};
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Relógio que o teste adianta. */
    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }
    }
}
