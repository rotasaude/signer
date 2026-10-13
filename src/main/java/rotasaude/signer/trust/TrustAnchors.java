package rotasaude.signer.trust;

import java.util.ServiceLoader;
import org.demoiselle.signer.core.ca.provider.ProviderCA;

/**
 * Âncoras de confiança carregadas (ICP-Brasil e, fora de produção, as extras). Sem nenhuma,
 * toda assinatura daria untrusted_chain: melhor não subir.
 */
public final class TrustAnchors {

    private TrustAnchors() {}

    public static int count() {
        int total = 0;
        for (ProviderCA provider : ServiceLoader.load(ProviderCA.class)) {
            try {
                total += provider.getCAs().size();
            } catch (RuntimeException e) {
                // provedor com problema não conta
            }
        }
        return total;
    }

    public static void requireAny() {
        requireAny(count());
    }

    static void requireAny(int count) {
        if (count <= 0) throw new IllegalStateException("nenhuma âncora de confiança carregada");
    }
}
