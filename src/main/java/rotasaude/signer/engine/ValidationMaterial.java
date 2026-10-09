package rotasaude.signer.engine;

import java.security.cert.X509Certificate;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CRLHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.demoiselle.signer.core.extension.ICPBR_CRL;
import org.demoiselle.signer.core.repository.CRLRepositoryFactory;
import rotasaude.signer.SignerFailure;

/**
 * Provas de validade do ato (ADR 0032): cadeia e LCRs vigentes, num CMS degenerado
 * (certs-only, RFC 5652 §5.1, sem signatário). LCR indisponível não impede: vai sem ela.
 */
public final class ValidationMaterial {

    private ValidationMaterial() {}

    public static byte[] collect(List<X509Certificate> chain) {
        try {
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addCertificates(new JcaCertStore(chain));
            for (X509Certificate certificate : chain) {
                if (certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) continue;
                try {
                    for (ICPBR_CRL crl : CRLRepositoryFactory.factoryCRLRepository().getX509CRL(certificate)) {
                        generator.addCRL(new JcaX509CRLHolder(crl.getCRL()));
                    }
                } catch (Exception unavailable) {
                    // segue sem a LCR deste elo; o /verify diz indeterminate
                }
            }
            return generator.generate(new CMSAbsentContent()).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new SignerFailure(SignerFailure.Code.INTERNAL);
        }
    }
}
