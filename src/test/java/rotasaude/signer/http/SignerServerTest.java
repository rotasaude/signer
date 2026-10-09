package rotasaude.signer.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import rotasaude.signer.Config;
import rotasaude.signer.devpki.DevPki;
import rotasaude.signer.engine.PreparedStateCodec;
import rotasaude.signer.engine.SignatureEngine;
import rotasaude.signer.support.TestPki;

class SignerServerTest {

    private static final String TOKEN = "dev-signer-token-0123456789abcdef";
    private static final String CLINICAL_MARKER = "Glicemia capilar 245 mg/dL";
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final TestPki PKI = TestPki.get();
    private static final HttpClient CLIENT = HttpClient.newHttpClient();
    private static final B64 B = new B64();

    private static HttpServer server;
    private static String base;
    private static Path devPkiDir;

    @BeforeAll
    static void start() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            port = socket.getLocalPort();
        }
        devPkiDir = Files.createTempDirectory("dev-pki");
        PKI.pki.writeTo(devPkiDir);
        server = SignerServer.start(Config.fromEnv(Map.of("SIGNER_TOKEN", TOKEN, "SIGNER_PORT", String.valueOf(port),
                "SIGNER_DEV_PKI_DIR", devPkiDir.toString())), new SignatureEngine(Clock.systemUTC()));
        base = "http://127.0.0.1:" + port;
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    private static HttpResponse<String> call(String method, String path, String token, String body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body))
                .header("Content-Type", "application/json");
        if (token != null) request.header("Authorization", "Bearer " + token);
        return CLIENT.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static JsonNode post(String path, ObjectNode body, int expectedStatus) throws Exception {
        HttpResponse<String> response = call("POST", path, TOKEN, body.toString());
        assertEquals(expectedStatus, response.statusCode(), response.body());
        return JSON.readTree(response.body());
    }

    private static ObjectNode prepareBody(String kind, byte[] document, DevPki.Issued professional) throws Exception {
        return JSON.createObjectNode().put("kind", kind).put("policy", "AD-RB")
                .put("document_base64", B.e(document)).put("certificate_der_base64", B.e(professional.certificate().getEncoded()));
    }

    private static JsonNode signOverHttp(String kind, byte[] document, DevPki.Issued professional) throws Exception {
        JsonNode prepared = post("/prepare", prepareBody(kind, document, professional), 200);
        String state = prepared.get("prepared_state").asText();
        byte[] attributes = new PreparedStateCodec(TOKEN).decode(state).signedAttributesDer();
        assertEquals(B.e(java.security.MessageDigest.getInstance("SHA-256").digest(attributes)),
                prepared.get("to_be_signed_sha256_base64").asText());
        return post("/assemble", JSON.createObjectNode().put("kind", kind).put("prepared_state", state)
                .put("signature_value_base64", B.e(TestPki.rawSign(professional.privateKey(), attributes))), 200);
    }

    @Test
    void refusesMissingAndWrongToken() throws Exception {
        assertEquals(401, call("GET", "/health", null, null).statusCode());
        HttpResponse<String> wrong = call("GET", "/health", "x".repeat(40), null);
        assertEquals(401, wrong.statusCode());
        assertEquals("{\"error\":\"unauthorized\"}", wrong.body());
    }

    @Test
    void healthReportsVersionAndCrlTime() throws Exception {
        HttpResponse<String> response = call("GET", "/health", TOKEN, null);
        assertEquals(200, response.statusCode());
        JsonNode body = JSON.readTree(response.body());
        assertEquals("dev", body.get("version").asText());
        assertTrue(body.has("crl_updated_at"));
    }

    @Test
    void cadesRoundTripOverHttp() throws Exception {
        byte[] document = ("{\"text\":\"" + CLINICAL_MARKER + "\"}").getBytes(StandardCharsets.UTF_8);
        JsonNode assembled = signOverHttp("cades", document, PKI.professional());
        JsonNode verified = post("/verify", JSON.createObjectNode().put("kind", "cades").put("document_base64", B.e(document))
                .put("signature_base64", assembled.get("signature_base64").asText()), 200);

        assertEquals("valid", verified.get("status").asText(), verified.toString());
        assertEquals(TestPki.CPF, verified.get("signer_cpf").asText());
        assertEquals(TestPki.NAME, verified.get("signer_name").asText());
        assertTrue(verified.get("signed_at").asText().endsWith("Z"));
        assertEquals(0, verified.get("reasons").size());
        assertFalse(assembled.get("validation_material_base64").asText().isEmpty());
    }

    @Test
    void padesRoundTripOverHttpWithoutDocument() throws Exception {
        JsonNode assembled = signOverHttp("pades", TestPki.samplePdf("Consulta"), PKI.professional());
        JsonNode verified = post("/verify", JSON.createObjectNode().put("kind", "pades")
                .put("signature_base64", assembled.get("signature_base64").asText()), 200);
        assertEquals("valid", verified.get("status").asText(), verified.toString());
    }

    @Test
    void certificateCheckOverHttp() throws Exception {
        DevPki.Issued professional = PKI.professional();
        String body = JSON.createObjectNode().put("certificate_der_base64", B.e(professional.certificate().getEncoded())).toString();

        assertEquals(401, call("POST", "/certificates/check", null, body).statusCode());
        JsonNode valid = post("/certificates/check", (ObjectNode) JSON.readTree(body), 200);
        assertEquals("valid", valid.get("status").asText(), valid.toString());
        assertEquals(TestPki.CPF, valid.get("signer_cpf").asText());
        assertEquals(professional.certificate().getNotAfter().toInstant().toString(), valid.get("not_after").asText());
        assertEquals(0, valid.get("reasons").size());

        JsonNode untrusted = post("/certificates/check", JSON.createObjectNode()
                .put("certificate_der_base64", B.e(TestPki.untrustedProfessional().certificate().getEncoded())), 200);
        assertEquals("invalid", untrusted.get("status").asText());
        assertEquals("untrusted_chain", untrusted.get("reasons").get(0).asText());

        assertEquals("invalid_certificate", post("/certificates/check", JSON.createObjectNode()
                .put("certificate_der_base64", B.e("not a certificate".getBytes(StandardCharsets.UTF_8))), 422).get("error").asText());
        assertEquals("invalid_request", post("/certificates/check", JSON.createObjectNode(), 400).get("error").asText());
    }

    @Test
    void contractErrors() throws Exception {
        DevPki.Issued professional = PKI.professional();
        byte[] json = "{}".getBytes(StandardCharsets.UTF_8);
        assertEquals("invalid_request", post("/prepare", prepareBody("xades", json, professional), 400).get("error").asText());
        assertEquals("invalid_request", post("/prepare", prepareBody("cades", json, professional).put("policy", "AD-RT"), 400).get("error").asText());
        assertEquals("invalid_request", post("/prepare", prepareBody("cades", json, professional).put("document_base64", "%%%"), 400).get("error").asText());
        assertEquals("invalid_certificate", post("/prepare", prepareBody("cades", json, professional)
                .put("certificate_der_base64", B.e("not a certificate".getBytes(StandardCharsets.UTF_8))), 422).get("error").asText());
        assertEquals("invalid_certificate", post("/prepare", prepareBody("cades", json, TestPki.untrustedProfessional()), 422).get("error").asText());

        JsonNode prepared = post("/prepare", prepareBody("cades", json, professional), 200);
        String state = prepared.get("prepared_state").asText();
        assertEquals("invalid_request", post("/assemble", JSON.createObjectNode().put("kind", "pades").put("prepared_state", state)
                .put("signature_value_base64", B.e(new byte[256])), 400).get("error").asText());
        assertEquals("invalid_signature_value", post("/assemble", JSON.createObjectNode().put("kind", "cades").put("prepared_state", state)
                .put("signature_value_base64", B.e(new byte[256])), 422).get("error").asText());
        assertEquals("invalid_request", post("/verify", JSON.createObjectNode().put("kind", "cades")
                .put("signature_base64", B.e(new byte[] {1})), 400).get("error").asText());
        assertEquals(400, call("POST", "/prepare", TOKEN, "not json").statusCode());
        assertEquals(404, call("GET", "/nothing", TOKEN, null).statusCode());
    }

    @Test
    void devPkiServesOnlyTheCrlsWithoutToken() throws Exception {
        assertEquals(200, call("GET", "/dev-pki/intermediate.crl", null, null).statusCode());
        assertEquals(200, call("GET", "/dev-pki/root.crl", null, null).statusCode());
        assertEquals(404, call("GET", "/dev-pki/intermediate.key.pem", null, null).statusCode());
        assertEquals(404, call("GET", "/dev-pki/../anchors.pem", null, null).statusCode());
    }

    @Test
    void logsNeverCarryTokenCpfNameOrDocument() throws Exception {
        PrintStream original = System.out;
        ByteArrayOutputStream captured = new ByteArrayOutputStream();
        System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
        try {
            byte[] document = ("{\"text\":\"" + CLINICAL_MARKER + "\"}").getBytes(StandardCharsets.UTF_8);
            JsonNode assembled = signOverHttp("cades", document, PKI.professional());
            post("/verify", JSON.createObjectNode().put("kind", "cades").put("document_base64", B.e(document))
                    .put("signature_base64", assembled.get("signature_base64").asText()), 200);
            post("/prepare", prepareBody("cades", document, TestPki.untrustedProfessional()), 422);
            signOverHttp("pades", TestPki.samplePdf(CLINICAL_MARKER), PKI.professional());
        } finally {
            System.setOut(original);
        }
        String log = captured.toString(StandardCharsets.UTF_8);
        assertTrue(log.contains("POST /prepare 200"), log);
        for (String secret : new String[] {TOKEN, TestPki.CPF, TestPki.NAME, CLINICAL_MARKER, "Glicemia"}) {
            assertFalse(log.contains(secret), "log contém " + secret + ":\n" + log);
        }
    }

    private static final class B64 {
        String e(byte[] bytes) {
            return Base64.getEncoder().encodeToString(bytes);
        }
    }
}
