package rotasaude.signer.engine;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import rotasaude.signer.SignerFailure;

/** As três operações do contrato §9 sobre bytes; o HTTP fica em rotasaude.signer.http. */
public final class SignatureEngine {

    public record Assembled(byte[] signature, byte[] validationMaterial) {}

    private final Clock clock;

    public SignatureEngine(Clock clock) {
        this.clock = clock;
    }

    public PreparedSignature prepare(Kind kind, byte[] document, byte[] certificateDer) {
        X509Certificate certificate = certificate(certificateDer);
        if (!"RSA".equals(certificate.getPublicKey().getAlgorithm())) {
            throw new SignerFailure(SignerFailure.Code.INVALID_CERTIFICATE);
        }
        Instant now = clock.instant();
        Policies.requireInForce(kind, now);
        Chain.of(certificate);
        if (kind == Kind.CADES) {
            return new PreparedSignature(kind, certificateDer, SignedAttributes.build(kind, document, certificate, now), null);
        }
        byte[] preparedPdf = PdfPlaceholder.prepare(document, now);
        byte[] content = PdfPlaceholder.signedContent(preparedPdf);
        return new PreparedSignature(kind, certificateDer, SignedAttributes.build(kind, content, certificate, now), preparedPdf);
    }

    public Assembled assemble(PreparedSignature prepared, byte[] rawSignature) {
        X509Certificate certificate = certificate(prepared.certificateDer());
        List<X509Certificate> chain = Chain.of(certificate);
        byte[] cms = CmsAssembler.assemble(prepared.signedAttributesDer(), certificate, chain, rawSignature);
        byte[] signature = prepared.kind() == Kind.CADES ? cms : PdfPlaceholder.inject(prepared.preparedPdf(), cms);
        return new Assembled(signature, ValidationMaterial.collect(chain));
    }

    public Verification verify(Kind kind, byte[] document, byte[] signature) {
        if (kind == Kind.CADES && document == null) throw new SignerFailure(SignerFailure.Code.INVALID_REQUEST);
        return SignatureVerifier.verify(kind, document, signature);
    }

    public CertificateCheck checkCertificate(byte[] certificateDer) {
        return CertificateCheck.of(certificateDer, clock.instant());
    }

    static X509Certificate certificate(byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        } catch (CertificateException | RuntimeException e) {
            throw new SignerFailure(SignerFailure.Code.INVALID_CERTIFICATE);
        }
    }
}
