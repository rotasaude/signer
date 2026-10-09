package rotasaude.signer.engine;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HexFormat;
import java.util.TimeZone;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import rotasaude.signer.SignerFailure;

/**
 * PDF com a assinatura reservada (assinatura invisível, SubFilter ETSI.CAdES.detached,
 * entrada M = instante da assinatura). O Demoiselle não manipula PDF (a documentação do
 * policy-impl-pades manda usar o PDFBox); a assinatura é em duas fases porque entre o
 * /prepare e o /assemble o hash vai ao PSC.
 */
public final class PdfPlaceholder {

    /** Bytes reservados para o CMS (cadeia ICP de 3–4 certificados cabe com folga). */
    public static final int SIGNATURE_SIZE = 24_576;

    private PdfPlaceholder() {}

    public static byte[] prepare(byte[] original, Instant signingTime) {
        try (PDDocument document = Loader.loadPDF(original);
             SignatureOptions options = new SignatureOptions()) {
            PDSignature signature = new PDSignature();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ETSI_CADES_DETACHED);
            Calendar when = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
            when.setTimeInMillis(signingTime.toEpochMilli());
            signature.setSignDate(when);
            options.setPreferredSignatureSize(SIGNATURE_SIZE);
            document.addSignature(signature, options);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ExternalSigningSupport external = document.saveIncrementalForExternalSigning(out);
            external.setSignature(new byte[0]); // grava o PDF com o espaço reservado em zeros
            return out.toByteArray();
        } catch (IOException | RuntimeException e) {
            throw new SignerFailure(SignerFailure.Code.INVALID_REQUEST);
        }
    }

    /** Bytes cobertos pela assinatura (tudo menos o valor de /Contents). */
    public static byte[] signedContent(byte[] preparedPdf) {
        int[] range = byteRange(preparedPdf);
        byte[] content = Arrays.copyOfRange(preparedPdf, range[0], range[0] + range[1]);
        byte[] tail = Arrays.copyOfRange(preparedPdf, range[2], range[2] + range[3]);
        byte[] joined = Arrays.copyOf(content, content.length + tail.length);
        System.arraycopy(tail, 0, joined, content.length, tail.length);
        return joined;
    }

    public static byte[] inject(byte[] preparedPdf, byte[] cms) {
        int[] range = byteRange(preparedPdf);
        int start = range[0] + range[1] + 1;      // depois do '<'
        int capacity = range[2] - 1 - start;      // antes do '>'
        byte[] hex = HexFormat.of().withUpperCase().formatHex(cms).getBytes(StandardCharsets.US_ASCII);
        if (hex.length > capacity) throw new SignerFailure(SignerFailure.Code.INTERNAL);
        byte[] signed = preparedPdf.clone();
        System.arraycopy(hex, 0, signed, start, hex.length);
        return signed;
    }

    static int[] byteRange(byte[] pdf) {
        try (PDDocument document = Loader.loadPDF(pdf)) {
            PDSignature signature = document.getLastSignatureDictionary();
            if (signature == null) throw new SignerFailure(SignerFailure.Code.INVALID_REQUEST);
            int[] range = signature.getByteRange();
            if (range == null || range.length != 4) throw new SignerFailure(SignerFailure.Code.INVALID_REQUEST);
            return range;
        } catch (IOException e) {
            throw new SignerFailure(SignerFailure.Code.INVALID_REQUEST);
        }
    }
}
