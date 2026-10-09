package rotasaude.signer.engine;

import java.security.cert.X509Certificate;
import java.util.List;
import org.demoiselle.signer.core.ca.manager.CAManager;
import rotasaude.signer.SignerFailure;

/** Cadeia montada pelas âncoras do Demoiselle (ICP-Brasil e, se configuradas, as extras). */
public final class Chain {

    private Chain() {}

    /** Titular, intermediária(s) e raiz confiável; menos que 3 elos = certificado recusado. */
    public static List<X509Certificate> of(X509Certificate certificate) {
        try {
            List<X509Certificate> chain = List.copyOf(CAManager.getInstance().getCertificateChain(certificate));
            if (chain.size() < 3 || !CAManager.getInstance().isRootCA(chain.get(chain.size() - 1))) {
                throw new SignerFailure(SignerFailure.Code.INVALID_CERTIFICATE);
            }
            return chain;
        } catch (SignerFailure e) {
            throw e;
        } catch (RuntimeException e) {
            throw new SignerFailure(SignerFailure.Code.INVALID_CERTIFICATE);
        }
    }
}
