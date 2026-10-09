package rotasaude.signer.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import rotasaude.signer.SignerFailure;
import rotasaude.signer.devpki.DevPki;
import rotasaude.signer.support.TestPki;

class CadesRoundTripTest {

    private static final TestPki PKI = TestPki.get();
    private static final byte[] JSON = "{\"schema\":\"rotasaude.consultation.v1\",\"text\":\"Glicemia 245\"}".getBytes(StandardCharsets.UTF_8);

    private final SignatureEngine engine = new SignatureEngine(Clock.systemUTC());

    @AfterEach
    void crlBack() {
        PKI.crlAvailable(true);
    }

    private byte[] sign(DevPki.Issued professional, byte[] document) throws Exception {
        PreparedSignature prepared = engine.prepare(Kind.CADES, document, professional.certificate().getEncoded());
        byte[] raw = TestPki.rawSign(professional.privateKey(), prepared.signedAttributesDer());
        return engine.assemble(prepared, raw).signature();
    }

    @Test
    void signsAndVerifiesDetachedCadesAdRb() throws Exception {
        Instant before = Instant.now().minusSeconds(1);
        byte[] p7s = sign(PKI.professional(), JSON);

        Verification result = engine.verify(Kind.CADES, JSON, p7s);

        assertEquals(List.of(), result.reasons());
        assertEquals(Verification.VALID, result.status());
        assertEquals(TestPki.CPF, result.signerCpf());
        assertEquals(TestPki.NAME, result.signerName());
        assertEquals(Policies.oid(Kind.CADES), result.policyOid());
        assertTrue(!result.signedAt().isBefore(before.minusSeconds(1)) && !result.signedAt().isAfter(Instant.now()));
    }

    @Test
    void toBeSignedIsTheSha256OfTheSignedAttributes() throws Exception {
        PreparedSignature prepared = engine.prepare(Kind.CADES, JSON, PKI.professional().certificate().getEncoded());
        assertArrayEquals(java.security.MessageDigest.getInstance("SHA-256").digest(prepared.signedAttributesDer()),
                prepared.toBeSignedSha256());
    }

    @Test
    void alteredDocumentIsInvalid() throws Exception {
        byte[] p7s = sign(PKI.professional(), JSON);
        byte[] altered = JSON.clone();
        altered[altered.length - 3] ^= 0x01;

        Verification result = engine.verify(Kind.CADES, altered, p7s);

        assertEquals(Verification.INVALID, result.status());
        assertTrue(result.reasons().contains("signature_mismatch"), result.reasons().toString());
    }

    @Test
    void alteredSignatureValueIsInvalid() throws Exception {
        byte[] p7s = sign(PKI.professional(), JSON);
        byte[] altered = p7s.clone();
        altered[altered.length - 10] ^= 0x01; // dentro do valor RSA, no fim do SignerInfo

        Verification result = engine.verify(Kind.CADES, JSON, altered);

        assertEquals(Verification.INVALID, result.status());
    }

    @Test
    void rawFromAnotherKeyIsRefusedAtAssemble() throws Exception {
        DevPki.Issued professional = PKI.professional();
        PreparedSignature prepared = engine.prepare(Kind.CADES, JSON, professional.certificate().getEncoded());
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        byte[] foreign = TestPki.rawSign(generator.generateKeyPair().getPrivate(), prepared.signedAttributesDer());

        SignerFailure failure = assertThrows(SignerFailure.class, () -> engine.assemble(prepared, foreign));
        assertEquals(SignerFailure.Code.INVALID_SIGNATURE_VALUE, failure.code);
    }

    @Test
    void expiredCertificateIsRefusedAtPrepare() throws Exception {
        byte[] der = PKI.expiredProfessional().certificate().getEncoded();
        SignerFailure failure = assertThrows(SignerFailure.class, () -> engine.prepare(Kind.CADES, JSON, der));
        assertEquals(SignerFailure.Code.INVALID_CERTIFICATE, failure.code);
    }

    @Test
    void certificateOutsideTheTrustAnchorsIsRefusedAtPrepare() throws Exception {
        byte[] der = TestPki.untrustedProfessional().certificate().getEncoded();
        SignerFailure failure = assertThrows(SignerFailure.class, () -> engine.prepare(Kind.CADES, JSON, der));
        assertEquals(SignerFailure.Code.INVALID_CERTIFICATE, failure.code);
    }

    @Test
    void certificateRevokedBeforeSigningIsInvalid() throws Exception {
        DevPki.Issued professional = PKI.professional();
        byte[] p7s = sign(professional, JSON);
        PKI.pki.revoke(professional.certificate().getSerialNumber(), Instant.now().minus(Duration.ofHours(1)));

        Verification result = engine.verify(Kind.CADES, JSON, p7s);

        assertEquals(Verification.INVALID, result.status(), result.reasons() + " " + result.signedAt());
        assertTrue(result.reasons().contains("certificate_revoked"), result.reasons().toString());
    }

    @Test
    void certificateRevokedAfterSigningIsIndeterminate() throws Exception {
        DevPki.Issued professional = PKI.professional();
        byte[] p7s = sign(professional, JSON);
        PKI.pki.revoke(professional.certificate().getSerialNumber(), Instant.now().plus(Duration.ofMinutes(1)));

        Verification result = engine.verify(Kind.CADES, JSON, p7s);

        assertEquals(Verification.INDETERMINATE, result.status());
        assertEquals(List.of("certificate_revoked_after_signing"), result.reasons());
    }

    @Test
    void unreachableCrlIsIndeterminate() throws Exception {
        byte[] p7s = sign(PKI.professional(), JSON);
        PKI.crlAvailable(false);

        Verification result = engine.verify(Kind.CADES, JSON, p7s);

        assertEquals(Verification.INDETERMINATE, result.status());
        assertEquals(List.of("revocation_unavailable"), result.reasons());
    }

    @Test
    void garbageSignatureIsMalformed() {
        Verification result = engine.verify(Kind.CADES, JSON, "not a cms".getBytes(StandardCharsets.UTF_8));
        assertEquals(Verification.INVALID, result.status());
        assertEquals(List.of("malformed_signature"), result.reasons());
    }

    @Test
    void cadesWithoutDocumentIsAnInvalidRequest() throws Exception {
        byte[] p7s = sign(PKI.professional(), JSON);
        SignerFailure failure = assertThrows(SignerFailure.class, () -> engine.verify(Kind.CADES, null, p7s));
        assertEquals(SignerFailure.Code.INVALID_REQUEST, failure.code);
    }

    @Test
    void validationMaterialCarriesTheChainAndTheCrls() throws Exception {
        DevPki.Issued professional = PKI.professional();
        PreparedSignature prepared = engine.prepare(Kind.CADES, JSON, professional.certificate().getEncoded());
        byte[] material = engine.assemble(prepared, TestPki.rawSign(professional.privateKey(), prepared.signedAttributesDer()))
                .validationMaterial();

        org.bouncycastle.cms.CMSSignedData bundle = new org.bouncycastle.cms.CMSSignedData(material);
        assertEquals(3, bundle.getCertificates().getMatches(null).size());
        assertEquals(2, bundle.getCRLs().getMatches(null).size());
        assertEquals(0, bundle.getSignerInfos().size());
    }
}
