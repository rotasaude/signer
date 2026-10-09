package rotasaude.signer.engine;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESSigner;
import rotasaude.signer.SignerFailure;

/**
 * Atributos assinados da política AD-RB, montados pelo Demoiselle sem chave privada
 * (CAdESSigner#prepareSignedAttributes é público e só precisa do certificado).
 * CAdES ganha signingTime (NGS2.02.03); PAdES não (o instante vai na entrada M do PDF).
 */
public final class SignedAttributes {

    private SignedAttributes() {}

    public static byte[] build(Kind kind, byte[] content, X509Certificate certificate, Instant signingTime) {
        CAdESSigner signer = new CAdESSigner(Policies.SIGNATURE_ALGORITHM, Policies.of(kind), kind == Kind.PADES);
        signer.setCertificates(new Certificate[] {certificate});
        signer.setHash(sha256(content));
        AttributeTable table;
        try {
            table = signer.prepareSignedAttributes(content, null);
            signer.prepareAlgAndLength();
        } catch (RuntimeException e) {
            // cadeia, validade, LCR ou tamanho de chave recusados pelo Demoiselle
            throw new SignerFailure(SignerFailure.Code.INVALID_CERTIFICATE);
        }
        if (kind == Kind.CADES && table.get(CMSAttributes.signingTime) == null) {
            table = table.add(CMSAttributes.signingTime, new Time(Date.from(signingTime.truncatedTo(ChronoUnit.SECONDS))));
        }
        try {
            return new DERSet(table.toASN1EncodableVector()).getEncoded(ASN1Encoding.DER);
        } catch (IOException e) {
            throw new SignerFailure(SignerFailure.Code.INTERNAL);
        }
    }

    static byte[] sha256(byte[] content) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
