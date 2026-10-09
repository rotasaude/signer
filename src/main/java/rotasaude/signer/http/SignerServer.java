package rotasaude.signer.http;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Set;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import rotasaude.signer.Config;
import rotasaude.signer.SignerFailure;
import rotasaude.signer.engine.CertificateCheck;
import rotasaude.signer.engine.Kind;
import rotasaude.signer.engine.PreparedSignature;
import rotasaude.signer.engine.PreparedStateCodec;
import rotasaude.signer.engine.SignatureEngine;
import rotasaude.signer.engine.TrackingCrlRepository;
import rotasaude.signer.engine.Verification;

/**
 * HTTP interno (contrato §9): JSON, Bearer compartilhado, corpo nunca logado.
 * O log de acesso tem só método, caminho, status e duração.
 */
public final class SignerServer {

    private static final Logger LOG = LogManager.getLogger(SignerServer.class);
    private static final int MAX_BODY = 48 * 1024 * 1024;
    private static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .streamReadConstraints(StreamReadConstraints.builder().maxStringLength(MAX_BODY).build()).build());
    private static final Set<String> DEV_PKI_FILES = Set.of("root.crl", "intermediate.crl");

    private final Config config;
    private final SignatureEngine engine;
    private final PreparedStateCodec codec;
    private final byte[] expectedAuthorization;

    private SignerServer(Config config, SignatureEngine engine) {
        this.config = config;
        this.engine = engine;
        this.codec = new PreparedStateCodec(config.token());
        this.expectedAuthorization = ("Bearer " + config.token()).getBytes(StandardCharsets.UTF_8);
    }

    public static HttpServer start(Config config, SignatureEngine engine) throws IOException {
        SignerServer handler = new SignerServer(config, engine);
        HttpServer server = HttpServer.create(new InetSocketAddress(config.port()), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/", handler::handle);
        if (config.devPkiDir() != null) server.createContext("/dev-pki/", handler::devPki);
        server.start();
        return server;
    }

    private void handle(HttpExchange exchange) throws IOException {
        long started = System.nanoTime();
        String route = exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath();
        int status = 500;
        try {
            if (!authorized(exchange)) throw new SignerFailure(SignerFailure.Code.UNAUTHORIZED);
            ObjectNode body = switch (route) {
                case "POST /prepare" -> prepare(read(exchange));
                case "POST /assemble" -> assemble(read(exchange));
                case "POST /verify" -> verify(read(exchange));
                case "POST /certificates/check" -> checkCertificate(read(exchange));
                case "GET /health" -> health();
                default -> null;
            };
            if (body == null) {
                status = 404;
                send(exchange, status, error("not_found"));
            } else {
                status = 200;
                send(exchange, status, body);
            }
        } catch (SignerFailure failure) {
            status = failure.code.status;
            send(exchange, status, error(failure.code.wire));
        } catch (Exception unexpected) {
            status = 500;
            LOG.error("{} failed: {}", route, unexpected.getClass().getSimpleName());
            send(exchange, status, error(SignerFailure.Code.INTERNAL.wire));
        } finally {
            LOG.info("{} {} {}ms", route, status, (System.nanoTime() - started) / 1_000_000);
        }
    }

    private ObjectNode prepare(JsonNode request) {
        Kind kind = Kind.parse(text(request, "kind"));
        if (!"AD-RB".equals(text(request, "policy"))) throw invalidRequest();
        PreparedSignature prepared = engine.prepare(kind, base64(request, "document_base64"), base64(request, "certificate_der_base64"));
        ObjectNode out = JSON.createObjectNode();
        out.put("to_be_signed_sha256_base64", Base64.getEncoder().encodeToString(prepared.toBeSignedSha256()));
        out.put("prepared_state", codec.encode(prepared));
        return out;
    }

    private ObjectNode assemble(JsonNode request) {
        Kind kind = Kind.parse(text(request, "kind"));
        PreparedSignature prepared = codec.decode(text(request, "prepared_state"));
        if (prepared.kind() != kind) throw invalidRequest();
        SignatureEngine.Assembled assembled = engine.assemble(prepared, base64(request, "signature_value_base64"));
        ObjectNode out = JSON.createObjectNode();
        out.put("signature_base64", Base64.getEncoder().encodeToString(assembled.signature()));
        out.put("validation_material_base64", Base64.getEncoder().encodeToString(assembled.validationMaterial()));
        return out;
    }

    private ObjectNode verify(JsonNode request) {
        Kind kind = Kind.parse(text(request, "kind"));
        JsonNode document = request.get("document_base64");
        // contrato §13: em PAdES o campo é ignorado (nem decodificado)
        byte[] documentBytes = kind != Kind.CADES || document == null || document.isNull() ? null : base64(request, "document_base64");
        Verification result = engine.verify(kind, documentBytes, base64(request, "signature_base64"));
        ObjectNode out = JSON.createObjectNode();
        out.put("status", result.status());
        out.put("signer_cpf", result.signerCpf());
        out.put("signer_name", result.signerName());
        out.put("policy_oid", result.policyOid());
        out.put("signed_at", result.signedAt() == null ? null : result.signedAt().toString());
        ArrayNode reasons = out.putArray("reasons");
        result.reasons().forEach(reasons::add);
        return out;
    }

    private ObjectNode checkCertificate(JsonNode request) {
        CertificateCheck result = engine.checkCertificate(base64(request, "certificate_der_base64"));
        ObjectNode out = JSON.createObjectNode();
        out.put("status", result.status());
        out.put("signer_cpf", result.signerCpf());
        out.put("not_after", result.notAfter().toString());
        ArrayNode reasons = out.putArray("reasons");
        result.reasons().forEach(reasons::add);
        return out;
    }

    private ObjectNode health() {
        Instant crl = TrackingCrlRepository.lastSuccess();
        ObjectNode out = JSON.createObjectNode();
        out.put("version", config.version());
        out.put("crl_updated_at", crl == null ? null : crl.toString());
        return out;
    }

    /** LCRs da AC de desenvolvimento, sem token (LCR é pública por natureza); nunca a chave. */
    private void devPki(HttpExchange exchange) throws IOException {
        String name = exchange.getRequestURI().getPath().substring("/dev-pki/".length());
        Path file = Path.of(config.devPkiDir(), name);
        if (!"GET".equals(exchange.getRequestMethod()) || !DEV_PKI_FILES.contains(name) || !Files.isRegularFile(file)) {
            send(exchange, 404, error("not_found"));
            return;
        }
        byte[] crl = Files.readAllBytes(file);
        exchange.getResponseHeaders().set("Content-Type", "application/pkix-crl");
        exchange.sendResponseHeaders(200, crl.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(crl);
        }
    }

    private boolean authorized(HttpExchange exchange) {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        return header != null && MessageDigest.isEqual(header.getBytes(StandardCharsets.UTF_8), expectedAuthorization);
    }

    private static JsonNode read(HttpExchange exchange) throws IOException {
        try (InputStream in = exchange.getRequestBody()) {
            byte[] raw = in.readNBytes(MAX_BODY + 1);
            if (raw.length > MAX_BODY) {
                in.readNBytes(8 * 1024 * 1024); // esgota um pouco do resto: fechar com o cliente ainda enviando o derruba com reset, sem ver o 400
                throw invalidRequest();
            }
            JsonNode node = JSON.readTree(raw);
            if (node == null || !node.isObject()) throw invalidRequest();
            return node;
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw invalidRequest();
        }
    }

    private static String text(JsonNode request, String field) {
        JsonNode value = request.get(field);
        if (value == null || !value.isTextual()) throw invalidRequest();
        return value.asText();
    }

    private static byte[] base64(JsonNode request, String field) {
        try {
            byte[] decoded = Base64.getDecoder().decode(text(request, field));
            if (decoded.length == 0) throw invalidRequest();
            return decoded;
        } catch (IllegalArgumentException e) {
            throw invalidRequest();
        }
    }

    private static SignerFailure invalidRequest() {
        return new SignerFailure(SignerFailure.Code.INVALID_REQUEST);
    }

    private static ObjectNode error(String code) {
        return JSON.createObjectNode().put("error", code);
    }

    private static void send(HttpExchange exchange, int status, ObjectNode body) throws IOException {
        byte[] bytes = JSON.writeValueAsBytes(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
