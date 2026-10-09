package rotasaude.signer.engine;

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import rotasaude.signer.SignerFailure;

/**
 * Monta o CMS destacado com a assinatura RAW devolvida pelo PSC (PKCS#1 v1.5 sobre os
 * atributos assinados). O Demoiselle não tem assinatura em duas fases sem chave privada
 * (prepare*Sign/envelop* exigem PrivateKey); o BouncyCastle (dependência do próprio
 * Demoiselle) fecha a lacuna com um ContentSigner que só devolve o valor já calculado.
 */
public final class CmsAssembler {

    private CmsAssembler() {}

    public static byte[] assemble(byte[] signedAttributesDer, X509Certificate certificate,
                                  List<X509Certificate> chain, byte[] rawSignature) {
        requireMatches(signedAttributesDer, certificate, rawSignature);
        try {
            AttributeTable table = new AttributeTable(ASN1Set.getInstance(signedAttributesDer));
            SignerInfoGenerator signerInfo = new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
                    .setSignedAttributeGenerator(new SimpleAttributeTableGenerator(table))
                    .build(new Precomputed(signedAttributesDer, rawSignature), certificate);
            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addSignerInfoGenerator(signerInfo);
            generator.addCertificates(new JcaCertStore(chain));
            return generator.generate(new CMSAbsentContent(), false).getEncoded(ASN1Encoding.DER);
        } catch (Exception e) {
            throw new SignerFailure(SignerFailure.Code.INTERNAL);
        }
    }

    /** RAW que não confere com a chave pública do certificado = 422 (nada é montado). */
    static void requireMatches(byte[] signedAttributesDer, X509Certificate certificate, byte[] rawSignature) {
        try {
            Signature verifier = Signature.getInstance(Policies.SIGNATURE_ALGORITHM);
            verifier.initVerify(certificate.getPublicKey());
            verifier.update(signedAttributesDer);
            if (verifier.verify(rawSignature)) return;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            // valor malformado cai no mesmo 422
        }
        throw new SignerFailure(SignerFailure.Code.INVALID_SIGNATURE_VALUE);
    }

    private static final class Precomputed implements ContentSigner {
        private final byte[] expected;
        private final byte[] signature;
        private final ByteArrayOutputStream written = new ByteArrayOutputStream();

        Precomputed(byte[] expected, byte[] signature) {
            this.expected = expected;
            this.signature = signature;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new DefaultSignatureAlgorithmIdentifierFinder().find(Policies.SIGNATURE_ALGORITHM);
        }

        @Override
        public OutputStream getOutputStream() {
            return written;
        }

        @Override
        public byte[] getSignature() {
            if (!Arrays.equals(written.toByteArray(), expected)) {
                throw new IllegalStateException("signed attributes differ from the prepared ones");
            }
            return signature.clone();
        }
    }
}
