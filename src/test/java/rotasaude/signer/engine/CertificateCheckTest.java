package rotasaude.signer.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import rotasaude.signer.SignerFailure;
import rotasaude.signer.devpki.DevPki;
import rotasaude.signer.support.TestPki;

class CertificateCheckTest {

    private static final TestPki PKI = TestPki.get();

    private final SignatureEngine engine = new SignatureEngine(Clock.systemUTC());

    @AfterEach
    void crlBack() {
        PKI.crlAvailable(true);
        PKI.crlMode(TestPki.CrlMode.GOOD);
    }

    @Test
    void activeCertificateIsValid() throws Exception {
        DevPki.Issued professional = PKI.professional();

        CertificateCheck result = engine.checkCertificate(professional.certificate().getEncoded());

        assertEquals(List.of(), result.reasons());
        assertEquals("valid", result.status());
        assertEquals(TestPki.CPF, result.signerCpf());
        assertEquals(professional.certificate().getNotAfter().toInstant(), result.notAfter());
    }

    @Test
    void revokedCertificateIsInvalid() throws Exception {
        DevPki.Issued professional = PKI.professional();
        PKI.pki.revoke(professional.certificate().getSerialNumber(), Instant.now().minus(Duration.ofMinutes(5)));

        CertificateCheck result = engine.checkCertificate(professional.certificate().getEncoded());

        assertEquals("invalid", result.status());
        assertEquals(List.of("certificate_revoked"), result.reasons());
    }

    @Test
    void expiredCertificateIsInvalid() throws Exception {
        CertificateCheck result = engine.checkCertificate(PKI.expiredProfessional().certificate().getEncoded());

        assertEquals("invalid", result.status());
        assertEquals(List.of("certificate_expired"), result.reasons());
    }

    @Test
    void certificateFromAnUnknownAuthorityIsInvalid() throws Exception {
        CertificateCheck result = engine.checkCertificate(TestPki.untrustedProfessional().certificate().getEncoded());

        assertEquals("invalid", result.status());
        assertEquals(List.of("untrusted_chain"), result.reasons());
        assertEquals(TestPki.CPF, result.signerCpf());
    }

    @Test
    void unreachableCrlIsIndeterminate() throws Exception {
        byte[] der = PKI.professional().certificate().getEncoded();
        PKI.crlAvailable(false);

        CertificateCheck result = engine.checkCertificate(der);

        assertEquals("indeterminate", result.status());
        assertEquals(List.of("revocation_unavailable"), result.reasons());
    }

    @Test
    void unreadableDerIsAnInvalidCertificate() {
        SignerFailure failure = assertThrows(SignerFailure.class,
                () -> engine.checkCertificate("not a certificate".getBytes(StandardCharsets.UTF_8)));
        assertEquals(SignerFailure.Code.INVALID_CERTIFICATE, failure.code);
    }

    @Test
    void crlSignedByAnotherKeyIsIndeterminate() throws Exception {
        byte[] der = PKI.professional().certificate().getEncoded();
        PKI.crlMode(TestPki.CrlMode.WRONG_KEY);

        CertificateCheck result = engine.checkCertificate(der);

        assertEquals("indeterminate", result.status());
        assertEquals(List.of("revocation_unavailable"), result.reasons());
    }

    @Test
    void expiredCrlIsIndeterminate() throws Exception {
        byte[] der = PKI.professional().certificate().getEncoded();
        PKI.crlMode(TestPki.CrlMode.EXPIRED);

        CertificateCheck result = engine.checkCertificate(der);

        assertEquals("indeterminate", result.status());
        assertEquals(List.of("revocation_unavailable"), result.reasons());
    }

    @Test
    void certificateOfARevokedIntermediateCaIsInvalid() throws Exception {
        java.math.BigInteger caSerial = PKI.pki.anchors().get(1).getSerialNumber();
        byte[] der = PKI.professional().certificate().getEncoded();
        PKI.pki.revoke(caSerial, Instant.now().minus(Duration.ofMinutes(5)));
        try {
            CertificateCheck result = engine.checkCertificate(der);

            assertEquals("invalid", result.status());
            assertEquals(List.of("certificate_revoked"), result.reasons());
        } finally {
            PKI.pki.unrevoke(caSerial);
        }
    }
}
