package rotasaude.signer;

import java.net.HttpURLConnection;
import java.net.URI;

/**
 * Sonda do HEALTHCHECK do container: GET /livez em localhost. A imagem só tem a JRE (sem
 * curl), e instalar ferramenta de rede só para isso aumentaria a superfície. Sai com 0 se
 * respondeu 200; 1 em qualquer outro caso.
 */
public final class HealthProbe {

    private HealthProbe() {}

    public static void main(String[] args) {
        int port = Config.DEFAULT_PORT;
        String raw = System.getenv("SIGNER_PORT");
        if (raw != null && !raw.isBlank()) {
            try {
                port = Integer.parseInt(raw.trim());
            } catch (NumberFormatException e) {
                System.exit(1);
            }
        }
        System.exit(check(port));
    }

    static int check(int port) {
        try {
            HttpURLConnection connection = (HttpURLConnection) URI.create("http://127.0.0.1:" + port + "/livez").toURL().openConnection();
            connection.setConnectTimeout(2000);
            connection.setReadTimeout(2000);
            try {
                return connection.getResponseCode() == 200 ? 0 : 1;
            } finally {
                connection.disconnect();
            }
        } catch (Exception e) {
            return 1;
        }
    }
}
