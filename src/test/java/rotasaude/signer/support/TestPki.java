package rotasaude.signer.support;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.font.Standard14Fonts;
import rotasaude.signer.devpki.DevPki;
import rotasaude.signer.trust.ConfiguredAnchorsProviderCA;

/**
 * AC de teste no formato ICP, uma por JVM, com as LCRs servidas num HTTP local
 * (o Demoiselle baixa a LCR pelo ponto de distribuição do certificado). As âncoras
 * entram pela configuração (propriedade signer.extraTrustAnchors), como em produção
 * entraria SIGNER_EXTRA_TRUST_ANCHORS em dev.
 */
public final class TestPki {

    public static final String CPF = "52998224725";
    public static final String NAME = "ANA BEATRIZ SOUZA";

    private static TestPki instance;

    public final DevPki pki;
    private volatile boolean crlAvailable = true;

    private TestPki() throws IOException {
        HttpServer crlServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        pki = DevPki.generate("http://127.0.0.1:" + crlServer.getAddress().getPort() + "/");
        crlServer.createContext("/", exchange -> {
            String name = exchange.getRequestURI().getPath().substring(1);
            byte[] body = crlAvailable ? pki.crl(name) : new byte[0];
            exchange.getResponseHeaders().set("Connection", "close"); // sem keep-alive: conexão velha reaproveitada estoura o timeout da LCR
            exchange.sendResponseHeaders(crlAvailable ? 200 : 503, crlAvailable ? body.length : -1);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        crlServer.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        crlServer.start();
        Path dir = Files.createTempDirectory("signer-test-pki");
        pki.writeTo(dir);
        System.setProperty(ConfiguredAnchorsProviderCA.PROPERTY, dir.resolve("anchors.pem").toString());
    }

    public static synchronized TestPki get() {
        if (instance == null) {
            try {
                instance = new TestPki();
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }
        return instance;
    }

    public DevPki.Issued professional() {
        Instant now = Instant.now();
        return pki.issue(CPF, NAME, LocalDate.of(1980, 5, 17), now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(365)));
    }

    public DevPki.Issued expiredProfessional() {
        Instant now = Instant.now();
        return pki.issue(CPF, NAME, LocalDate.of(1980, 5, 17), now.minus(Duration.ofDays(730)), now.minus(Duration.ofDays(365)));
    }

    /** O mesmo e-CPF, emitido por uma AC que não está nas âncoras. */
    public static DevPki.Issued untrustedProfessional() {
        Instant now = Instant.now();
        return DevPki.generate("http://127.0.0.1:9/").issue(CPF, NAME, LocalDate.of(1980, 5, 17),
                now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(365)));
    }

    public void crlAvailable(boolean available) {
        crlAvailable = available;
    }

    /** O que o PSC devolve em signature_format RAW: PKCS#1 v1.5 SHA-256 sobre os atributos assinados. */
    public static byte[] rawSign(PrivateKey key, byte[] signedAttributesDer) {
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(signedAttributesDer);
            return signature.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] samplePdf(String text) {
        try (PDDocument document = new PDDocument()) {
            PDPage page = new PDPage();
            document.addPage(page);
            try (PDPageContentStream content = new PDPageContentStream(document, page)) {
                content.beginText();
                content.setFont(new PDType1Font(Standard14Fonts.FontName.HELVETICA), 12);
                content.newLineAtOffset(72, 720);
                content.showText(text);
                content.endText();
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            document.save(out);
            return out.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
