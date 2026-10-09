package rotasaude.signer.engine;

import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicReference;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.repository.CRLRepository;
import org.demoiselle.signer.core.repository.ConfigurationRepo;
import org.demoiselle.signer.core.repository.OnLineCRLRepository;

/**
 * Repositório de LCR do Demoiselle (registrado por ServiceLoader): baixa como o
 * OnLineCRLRepository e anota o instante do último download bem-sucedido (/health).
 */
public final class TrackingCrlRepository implements CRLRepository {

    private static final AtomicReference<Instant> LAST_SUCCESS = new AtomicReference<>();

    public static Instant lastSuccess() {
        return LAST_SUCCESS.get();
    }

    @Override
    public Collection<ICPBR_CRL> getX509CRL(X509Certificate certificate) throws NoSuchProviderException {
        Collection<ICPBR_CRL> crls = new OnLineCRLRepository(ConfigurationRepo.getInstance().getProxy()).getX509CRL(certificate);
        if (crls != null && !crls.isEmpty()) LAST_SUCCESS.set(Instant.now());
        return crls;
    }
}
