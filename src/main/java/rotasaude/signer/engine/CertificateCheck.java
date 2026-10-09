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
        boolean trusted;
        try {
            Chain.of(certificate);
            trusted = true;
        } catch (SignerFailure untrusted) {
            trusted = false;
            reasons.add("untrusted_chain");
        }
        if (now.isBefore(certificate.getNotBefore().toInstant()) || now.isAfter(certificate.getNotAfter().toInstant())) {
            reasons.add("certificate_expired");
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage == null || !keyUsage[0] || !keyUsage[1]) reasons.add("key_usage");
        if (trusted) { // LCR de AC desconhecida não diz nada: nem se consulta
            String revocation = SignatureVerifier.revocation(certificate, null);
            if (revocation != null) reasons.add(revocation);
        }
        List<String> fixed = List.copyOf(reasons);
        return new CertificateCheck(SignatureVerifier.status(fixed), SignatureVerifier.cpf(certificate),
                certificate.getNotAfter().toInstant(), fixed);
    }
}
