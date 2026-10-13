package rotasaude.signer.engine;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.esf.SignaturePolicyId;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.extension.ICPBRCertificatePF;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.ValidationMessageCode;
import org.demoiselle.signer.policy.impl.cades.pkcs7.impl.CAdESChecker;
import org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESChecker;
import rotasaude.signer.SignerFailure;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

/**
 * Validação no servidor (NGS2.03): criptografia e atributos obrigatórios pelo checker do
 * Demoiselle; política, cadeia, instante, keyUsage e revogação conferidos aqui, com motivo.
 * Qualquer motivo de recusa → invalid; só motivos de dúvida → indeterminate.
 */
public final class SignatureVerifier {

    /** Tolerância de relógio entre quem assina e quem verifica. */
    static final java.time.Duration CLOCK_SKEW = java.time.Duration.ofMinutes(5);

    static final Set<String> INDETERMINATE_REASONS = Set.of("revocation_unavailable", "certificate_revoked_after_signing");

    private SignatureVerifier() {}

    public static Verification verify(Kind kind, byte[] document, byte[] signature, Instant now) {
        byte[] content;
        byte[] cms;
        Instant pdfSignDate = null;
        List<String> reasons = new ArrayList<>();
        if (kind == Kind.CADES) {
            content = document;
            cms = signature;
        } else {
            try (PDDocument pdf = Loader.loadPDF(signature)) {
                PDSignature dictionary = pdf.getLastSignatureDictionary();
                if (dictionary == null) return Verification.malformed();
                int[] range = dictionary.getByteRange();
                if (range == null || range.length != 4) return Verification.malformed();
                if ((long) range[2] + range[3] != signature.length) reasons.add("pdf_modified_after_signing");
                content = dictionary.getSignedContent(signature);
                cms = canonical(dictionary.getContents(signature));
                if (dictionary.getSignDate() != null) pdfSignDate = dictionary.getSignDate().toInstant();
            } catch (Exception e) {
                return Verification.malformed();
            }
        }

        SignerInformation signer;
        X509Certificate certificate;
        try {
            CMSSignedData data = new CMSSignedData(new CMSProcessableByteArray(content), cms);
            Collection<SignerInformation> signers = data.getSignerInfos().getSigners();
            if (signers.size() != 1) return Verification.malformed();
            signer = signers.iterator().next();
            @SuppressWarnings("unchecked")
            Collection<X509CertificateHolder> matches = data.getCertificates().getMatches(signer.getSID());
            if (matches.isEmpty()) return Verification.malformed();
            certificate = new JcaX509CertificateConverter().getCertificate(matches.iterator().next());
        } catch (Exception e) {
            return Verification.malformed();
        }

        String policyOid = policyOid(signer.getSignedAttributes());
        Instant signedAt = kind == Kind.CADES ? signingTime(signer.getSignedAttributes()) : pdfSignDate;

        List<X509Certificate> chain;
        try {
            chain = Chain.of(certificate);
        } catch (SignerFailure untrusted) {
            // Cadeia desconhecida: nada de rede (o checker do Demoiselle baixa LCR) e nada do titular.
            reasons.add("untrusted_chain");
            if (policyOid == null || !Policies.acceptedOids(kind).contains(policyOid)) reasons.add("policy_mismatch");
            List<String> unique = List.copyOf(new LinkedHashSet<>(reasons));
            return new Verification(status(unique), null, null, policyOid, signedAt, unique);
        }

        List<SignatureInformations> infos;
        try {
            infos = (kind == Kind.CADES ? new CAdESChecker() : new PAdESChecker()).checkDetachedSignature(content, cms);
        } catch (RuntimeException mismatch) {
            infos = null;
            reasons.add("signature_mismatch");
        }
        if (infos != null) {
            if (infos.size() != 1) return Verification.malformed();
            SignatureInformations info = infos.get(0);
            if (info.isInvalidSignature()) reasons.add("signature_mismatch");
            for (ValidationMessageCode code : info.getValidatorErrorCodes()) reasons.add(reasonFor(code));
            for (ValidationMessageCode code : info.getValidatorWarningCodes()) {
                if (code == ValidationMessageCode.POLICY_NOT_FOUND || code == ValidationMessageCode.PKCS7_ATTRIBUTE_NOT_FOUND) {
                    reasons.add("policy_mismatch");
                }
            }
            if (info.getChain() == null || info.getChain().size() < 3) reasons.add("untrusted_chain");
        }

        if (policyOid == null || !Policies.acceptedOids(kind).contains(policyOid)) reasons.add("policy_mismatch");
        if (signedAt == null) {
            reasons.add("signing_time_missing");
        } else if (signedAt.isAfter(now.plus(CLOCK_SKEW))) {
            reasons.add("signed_in_future");
        } else if (signedAt.isBefore(certificate.getNotBefore().toInstant()) || signedAt.isAfter(certificate.getNotAfter().toInstant())) {
            reasons.add("certificate_expired");
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage == null || !keyUsage[0] || !keyUsage[1]) reasons.add("key_usage");
        reasons.removeIf("revocation_unavailable"::equals); // o checker do Demoiselle não autentica LCR: quem decide é Revocation
        reasons.addAll(Revocation.reasons(chain, signedAt, now));

        List<String> unique = List.copyOf(new LinkedHashSet<>(reasons));
        return new Verification(status(unique), cpf(certificate), name(certificate), policyOid, signedAt, unique);
    }

    /** Nenhum motivo → valid; só motivos de dúvida → indeterminate; qualquer outro → invalid. */
    static String status(List<String> reasons) {
        if (reasons.isEmpty()) return Verification.VALID;
        return reasons.stream().allMatch(INDETERMINATE_REASONS::contains) ? Verification.INDETERMINATE : Verification.INVALID;
    }

    private static String reasonFor(ValidationMessageCode code) {
        return switch (code) {
            case CRL_NOT_ACCESS -> "revocation_unavailable"; // refeito abaixo por revocation()
            case CERTIFICATE_CHAIN_FAILED -> "untrusted_chain";
            case SIGNED_ATTRIBUTE_NOT_FOUND, PKCS7_ATTRIBUTE_NOT_FOUND, POLICY_NOT_FOUND -> "policy_mismatch";
            case INVALID_SIGNATURE, SIGNATURE_INVALID, SIGNATURE_MISMATCH, SIGNATURE_MISMATCH_DIGEST -> "signature_mismatch";
            default -> code.name().toLowerCase(Locale.ROOT);
        };
    }

    private static String policyOid(AttributeTable attributes) {
        if (attributes == null) return null;
        Attribute attribute = attributes.get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId);
        if (attribute == null) return null;
        try {
            ASN1Encodable value = attribute.getAttrValues().getObjectAt(0);
            return SignaturePolicyId.getInstance(value).getSigPolicyId().getId();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Instant signingTime(AttributeTable attributes) {
        if (attributes == null) return null;
        Attribute attribute = attributes.get(CMSAttributes.signingTime);
        if (attribute == null) return null;
        try {
            return Time.getInstance(attribute.getAttrValues().getObjectAt(0)).getDate().toInstant();
        } catch (RuntimeException e) {
            return null;
        }
    }

    static String cpf(X509Certificate certificate) {
        try {
            BasicCertificate basic = new BasicCertificate(certificate);
            ICPBRCertificatePF pf = basic.hasCertificatePF() ? basic.getICPBRCertificatePF() : null;
            String cpf = pf == null ? null : pf.getCPF();
            return cpf == null ? null : cpf.replaceAll("\\D", "");
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** CN da ICP-Brasil é "NOME DO TITULAR:CPF"; devolve só o nome. */
    private static String name(X509Certificate certificate) {
        try {
            for (Rdn rdn : new LdapName(certificate.getSubjectX500Principal().getName()).getRdns()) {
                if ("CN".equalsIgnoreCase(rdn.getType())) {
                    String cn = rdn.getValue().toString();
                    int colon = cn.indexOf(':');
                    return colon < 0 ? cn : cn.substring(0, colon);
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    /** /Contents vem com zeros de enchimento depois do DER; o checker recebe só o DER. */
    private static byte[] canonical(byte[] padded) throws java.io.IOException {
        try (ASN1InputStream in = new ASN1InputStream(padded)) {
            ASN1Primitive object = in.readObject();
            return ContentInfo.getInstance(object).getEncoded("DER");
        }
    }
}
