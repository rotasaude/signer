package rotasaude.signer.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Arrays;
import java.util.List;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.jupiter.api.Test;
import rotasaude.signer.SignerFailure;
import rotasaude.signer.devpki.DevPki;
import rotasaude.signer.support.TestPki;

class PadesRoundTripTest {

    private static final TestPki PKI = TestPki.get();

    private final SignatureEngine engine = new SignatureEngine(Clock.systemUTC());

    private byte[] signedPdf() throws Exception {
        DevPki.Issued professional = PKI.professional();
        PreparedSignature prepared = engine.prepare(Kind.PADES, TestPki.samplePdf("Consulta de teste"), professional.certificate().getEncoded());
        return engine.assemble(prepared, TestPki.rawSign(professional.privateKey(), prepared.signedAttributesDer())).signature();
    }

    @Test
    void signsAndVerifiesPadesAdRb() throws Exception {
        byte[] pdf = signedPdf();

        Verification result = engine.verify(Kind.PADES, null, pdf);

        assertEquals(List.of(), result.reasons());
        assertEquals(Verification.VALID, result.status());
        assertEquals(TestPki.CPF, result.signerCpf());
        assertEquals(Policies.oid(Kind.PADES), result.policyOid());
        try (PDDocument document = Loader.loadPDF(pdf)) {
            PDSignature signature = document.getLastSignatureDictionary();
            assertEquals(PDSignature.SUBFILTER_ETSI_CADES_DETACHED.getName(), signature.getSubFilter());
            assertEquals(signature.getSignDate().toInstant(), result.signedAt());
        }
    }

    @Test
    void bytesAppendedAfterSigningAreInvalid() throws Exception {
        byte[] pdf = signedPdf();
        byte[] appended = Arrays.copyOf(pdf, pdf.length + 12);
        System.arraycopy("\n%tampered\n".getBytes(StandardCharsets.US_ASCII), 0, appended, pdf.length, 11);

        Verification result = engine.verify(Kind.PADES, null, appended);

        assertEquals(Verification.INVALID, result.status());
        assertTrue(result.reasons().contains("pdf_modified_after_signing"), result.reasons().toString());
    }

    @Test
    void alteredSignedByteIsInvalid() throws Exception {
        byte[] pdf = signedPdf();
        byte[] altered = pdf.clone();
        altered[11] ^= 0x01; // comentário binário da 2ª linha do cabeçalho: o PDF continua legível

        Verification result = engine.verify(Kind.PADES, null, altered);

        assertEquals(Verification.INVALID, result.status());
        assertTrue(result.reasons().contains("signature_mismatch"), result.reasons().toString());
    }

    @Test
    void notAPdfIsAnInvalidRequestAtPrepare() throws Exception {
        byte[] der = PKI.professional().certificate().getEncoded();
        SignerFailure failure = assertThrows(SignerFailure.class,
                () -> engine.prepare(Kind.PADES, "not a pdf".getBytes(StandardCharsets.US_ASCII), der));
        assertEquals(SignerFailure.Code.INVALID_REQUEST, failure.code);
    }

    @Test
    void unsignedPdfIsMalformed() {
        Verification result = engine.verify(Kind.PADES, null, TestPki.samplePdf("sem assinatura"));
        assertEquals(List.of("malformed_signature"), result.reasons());
    }
}
