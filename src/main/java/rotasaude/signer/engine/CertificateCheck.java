package rotasaude.signer.engine;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import rotasaude.signer.SignerFailure;

/**
 * Conferência do certificado no vínculo (POST /certificates/check): cadeia até âncora
 * confiável, validade agora, keyUsage e LCR — o mesmo vocabulário de motivos do /verify.
 * DER ilegível ou chave não RSA = 422 invalid_certificate; o resto vira status + motivos.
 */
public record CertificateCheck(String status, String signerCpf, Instant notAfter, List<String> reasons) {

    public static CertificateCheck of(byte[] certificateDer, Instant now) {
        X509Certificate certificate = SignatureEngine.certificate(certificateDer);
        if (!"RSA".equals(certificate.getPublicKey().getAlgorithm())) {
            throw new SignerFailure(SignerFailure.Code.INVALID_CERTIFICATE);
        }
        List<String> reasons = new ArrayList<>();
        List<X509Certificate> chain = null;
        try {
            chain = Chain.of(certificate);
        } catch (SignerFailure untrusted) {
            reasons.add("untrusted_chain");
        }
        if (now.isBefore(certificate.getNotBefore().toInstant()) || now.isAfter(certificate.getNotAfter().toInstant())) {
            reasons.add("certificate_expired");
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage == null || !keyUsage[0] || !keyUsage[1]) reasons.add("key_usage");
        if (chain != null) { // LCR de AC desconhecida não diz nada: nem se consulta
            reasons.addAll(Revocation.reasons(chain, null, now));
        }
        List<String> fixed = List.copyOf(reasons);
        return new CertificateCheck(SignatureVerifier.status(fixed), SignatureVerifier.cpf(certificate),
                certificate.getNotAfter().toInstant(), fixed);
    }
}
