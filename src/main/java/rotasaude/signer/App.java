package rotasaude.signer;

import java.time.Clock;
import org.apache.logging.log4j.LogManager;
import rotasaude.signer.engine.CrlFetcher;
import rotasaude.signer.engine.CrlUrlPolicy;
import rotasaude.signer.engine.SignatureEngine;
import rotasaude.signer.engine.TrackingCrlRepository;
import rotasaude.signer.http.SignerServer;

public final class App {

    private App() {}

    public static void main(String[] args) throws Exception {
        Config config;
        try {
            config = Config.fromEnv(System.getenv());
        } catch (IllegalArgumentException e) {
            System.err.println("signer: " + e.getMessage());
            System.exit(1);
            return;
        }
        TrackingCrlRepository.configure(new CrlFetcher(
                new CrlUrlPolicy("production".equals(config.environment()), CrlUrlPolicy::resolve),
                Clock.systemUTC(), TrackingCrlRepository.maxAgeFromProperty(), TrackingCrlRepository.timeoutFromEnv()));
        SignerServer.start(config, new SignatureEngine(Clock.systemUTC()));
        LogManager.getLogger(App.class).info("signer {} listening on {}", config.version(), config.port());
    }
}
