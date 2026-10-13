package rotasaude.signer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sun.net.httpserver.HttpServer;
import java.net.ServerSocket;
import java.time.Clock;
import java.util.Map;
import org.junit.jupiter.api.Test;
import rotasaude.signer.engine.SignatureEngine;
import rotasaude.signer.http.SignerServer;

/** Sonda do HEALTHCHECK do container (R1, signer#1 item 8). */
class HealthProbeTest {

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    @Test
    void healthyWhenLivezAnswers() throws Exception {
        int port = freePort();
        HttpServer server = SignerServer.start(Config.fromEnv(Map.of("SIGNER_TOKEN", "t".repeat(32), "SIGNER_ENV", "development",
                "SIGNER_PORT", String.valueOf(port))), new SignatureEngine(Clock.systemUTC()));
        try {
            assertEquals(0, HealthProbe.check(port));
        } finally {
            server.stop(0);
        }
    }

    @Test
    void unhealthyWhenNothingListens() throws Exception {
        assertEquals(1, HealthProbe.check(freePort()));
    }
}
