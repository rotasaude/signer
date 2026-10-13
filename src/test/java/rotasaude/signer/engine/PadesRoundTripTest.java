package rotasaude.signer.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

    // ---- R1 (signer#1): item 4, auto-verificação do PDF produzido ----

    @Test
    void assembledPdfThatDoesNotVerifyIsRefused() throws Exception {
        DevPki.Issued professional = PKI.professional();
        byte[] der = professional.certificate().getEncoded();
        PreparedSignature first = engine.prepare(Kind.PADES, TestPki.samplePdf("Consulta A"), der);
        PreparedSignature other = engine.prepare(Kind.PADES, TestPki.samplePdf("Consulta B"), der);
        // Atributos (e valor RSA) do primeiro, PDF do segundo: o CMS é bom, o PDF montado não confere.
        PreparedSignature mixed = new PreparedSignature(Kind.PADES, der, first.signedAttributesDer(), other.preparedPdf());
        byte[] raw = TestPki.rawSign(professional.privateKey(), first.signedAttributesDer());

        SignerFailure failure = assertThrows(SignerFailure.class, () -> engine.assemble(mixed, raw));
        assertEquals(SignerFailure.Code.ASSEMBLED_SIGNATURE_INVALID, failure.code);
    }

    // ---- R1 (signer#1): item 7, ByteRange estrito ----

    @Test
    void strictByteRangeAcceptsOnlyTheExactContentsGap() throws Exception {
        byte[] pdf = signedPdf();
        int[] r;
        try (PDDocument document = Loader.loadPDF(pdf)) {
            r = document.getLastSignatureDictionary().getByteRange();
        }

        assertTrue(SignatureVerifier.strictByteRange(r, pdf));
        assertFalse(SignatureVerifier.strictByteRange(new int[] {1, r[1] - 1, r[2], r[3]}, pdf), "não começa no zero");
        assertFalse(SignatureVerifier.strictByteRange(new int[] {0, r[2] + 1, r[2], r[3]}, pdf), "intervalos sobrepostos");
        assertFalse(SignatureVerifier.strictByteRange(new int[] {0, r[1], r[2] + 2, r[3] - 2}, pdf), "vão maior que o /Contents");
        assertFalse(SignatureVerifier.strictByteRange(new int[] {0, r[1] + 1, r[2], r[3]}, pdf), "vão menor que o /Contents");
        assertFalse(SignatureVerifier.strictByteRange(new int[] {0, -5, r[2], r[3]}, pdf), "negativo");
        assertFalse(SignatureVerifier.strictByteRange(new int[] {0, r[1], r[2]}, pdf), "três valores");
    }

    @Test
    void byteRangeRewrittenInTheFileIsInvalid() throws Exception {
        byte[] pdf = signedPdf();
        String text = new String(pdf, StandardCharsets.ISO_8859_1);
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("/ByteRange\\s*\\[\\s*0\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s*\\]").matcher(text);
        assertTrue(m.find());
        String original = m.group();
        String forged = "/ByteRange [0 " + (Integer.parseInt(m.group(1)) + 1) + " " + m.group(2) + " " + m.group(3) + "]";
        forged = forged + " ".repeat(Math.max(0, original.length() - forged.length())); // mesmo tamanho: o xref não se mexe
        byte[] altered = (text.substring(0, m.start()) + forged + text.substring(m.end())).getBytes(StandardCharsets.ISO_8859_1);

        Verification result = engine.verify(Kind.PADES, null, altered);

        assertEquals(Verification.INVALID, result.status());
        assertTrue(result.reasons().contains("pdf_byte_range_invalid"), result.reasons().toString());
    }
}

