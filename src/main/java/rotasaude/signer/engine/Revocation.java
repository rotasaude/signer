package rotasaude.signer.engine;

import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.repository.CRLRepositoryFactory;

/**
 * Revogação de cada elo da cadeia (titular e ACs intermediárias; a raiz é âncora). A LCR é baixada
 * uma só vez por elo e só vale se for autêntica (assinada pela AC emissora do elo, emitente igual
 * ao emissor do certificado) e vigente (thisUpdate <= agora <= nextUpdate; sem nextUpdate = falha).
 * Qualquer falha vira revocation_unavailable (indeterminate), nunca valid. Revogado antes ou no
 * instante da assinatura (ou sem instante, no vínculo) = certificate_revoked; depois =
 * certificate_revoked_after_signing.
 */
final class Revocation {

    private Revocation() {}

    /** Motivos de revogação, sem repetição, para a cadeia [titular, ..., raiz]; signedAt pode ser null. */
    static List<String> reasons(List<X509Certificate> chain, Instant signedAt, Instant now) {
        List<String> reasons = new ArrayList<>();
        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate certificate = chain.get(i);
            if (certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) continue;
            String reason = reasonFor(certificate, chain.get(i + 1), signedAt, now);
            if (reason != null && !reasons.contains(reason)) reasons.add(reason);
        }
        return reasons;
    }

    private static String reasonFor(X509Certificate certificate, X509Certificate issuer, Instant signedAt, Instant now) {
        X509CRL crl = authenticCrl(certificate, issuer, now);
        if (crl == null) return "revocation_unavailable";
        X509CRLEntry entry = crl.getRevokedCertificate(certificate);
        if (entry == null) return null;
        if (signedAt == null || !entry.getRevocationDate().toInstant().isAfter(signedAt)) return "certificate_revoked";
        return "certificate_revoked_after_signing";
    }

    private static X509CRL authenticCrl(X509Certificate certificate, X509Certificate issuer, Instant now) {
        try {
            Collection<ICPBR_CRL> crls = CRLRepositoryFactory.factoryCRLRepository().getX509CRL(certificate);
            if (crls == null) return null;
            for (ICPBR_CRL candidate : crls) {
                X509CRL crl = candidate.getCRL();
                if (crl != null && authentic(crl, certificate, issuer, now)) return crl;
            }
        } catch (Exception unavailable) {
            // download, parse ou repositório: sem LCR confiável
        }
        return null;
    }

    private static boolean authentic(X509CRL crl, X509Certificate certificate, X509Certificate issuer, Instant now) {
        try {
            if (!crl.getIssuerX500Principal().equals(certificate.getIssuerX500Principal())) return false;
            crl.verify(issuer.getPublicKey());
            if (crl.getNextUpdate() == null) return false;
            return !now.isBefore(crl.getThisUpdate().toInstant()) && !now.isAfter(crl.getNextUpdate().toInstant());
        } catch (Exception e) {
            return false;
        }
    }
}
