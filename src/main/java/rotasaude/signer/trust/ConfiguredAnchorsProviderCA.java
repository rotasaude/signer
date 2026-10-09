package rotasaude.signer.trust;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.demoiselle.signer.core.ca.provider.ProviderCA;

/**
 * Âncoras extras (PEM) por configuração: SIGNER_EXTRA_TRUST_ANCHORS ou a propriedade
 * signer.extraTrustAnchors. Só AC de teste/desenvolvimento; proibido com SIGNER_ENV=production
 * (Config recusa o boot). Lido a cada chamada: o teste escreve o arquivo antes de usar.
 */
public final class ConfiguredAnchorsProviderCA implements ProviderCA {

    public static final String ENV = "SIGNER_EXTRA_TRUST_ANCHORS";
    public static final String PROPERTY = "signer.extraTrustAnchors";

    @Override
    public String getName() {
        return "rotasaude-extra-anchors";
    }

    @Override
    public Collection<X509Certificate> getCAs() {
        String path = System.getenv(ENV);
        if (path == null || path.isBlank()) path = System.getProperty(PROPERTY);
        if (path == null || path.isBlank()) return List.of();
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            List<X509Certificate> anchors = new ArrayList<>();
            for (Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                anchors.add((X509Certificate) certificate);
            }
            return anchors;
        } catch (Exception e) {
            return List.of();
        }
    }
}
