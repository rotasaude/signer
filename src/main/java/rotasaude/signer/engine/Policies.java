package rotasaude.signer.engine;

import java.time.Instant;
import java.util.Date;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.demoiselle.signer.policy.engine.asn1.etsi.SignaturePolicy;
import org.demoiselle.signer.policy.engine.asn1.etsi.SigningPeriod;
import org.demoiselle.signer.policy.engine.factory.PolicyFactory;
import rotasaude.signer.SignerFailure;

/**
 * Políticas AD-RB do Demoiselle (artefatos da LPA embutidos no jar, sem rede).
 * CAdES: a padrão do CAdESSigner 4.6.2; PAdES: a padrão do PAdESSigner 4.6.2.
 * O OID nunca é fixado no código: sai do .der da política.
 */
public final class Policies {

    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private static final Map<Kind, PolicyFactory.Policies> CURRENT = new EnumMap<>(Map.of(
            Kind.CADES, PolicyFactory.Policies.AD_RB_CADES_2_4,
            Kind.PADES, PolicyFactory.Policies.AD_RB_PADES_1_3));

    private static final Map<Kind, Set<String>> ACCEPTED = new EnumMap<>(Kind.class);

    private Policies() {}

    public static PolicyFactory.Policies of(Kind kind) {
        return CURRENT.get(kind);
    }

    public static SignaturePolicy load(PolicyFactory.Policies policy) {
        return PolicyFactory.getInstance().loadPolicy(policy);
    }

    public static String oid(Kind kind) {
        return load(of(kind)).getSignPolicyInfo().getSignPolicyIdentifier().getValue();
    }

    /** OIDs de todas as versões AD-RB do formato: assinatura antiga continua verificável. */
    public static synchronized Set<String> acceptedOids(Kind kind) {
        return ACCEPTED.computeIfAbsent(kind, k -> {
            String prefix = k == Kind.CADES ? "AD_RB_CADES_" : "AD_RB_PADES_";
            Set<String> oids = new HashSet<>();
            for (PolicyFactory.Policies p : PolicyFactory.Policies.values()) {
                if (p.name().startsWith(prefix)) {
                    oids.add(load(p).getSignPolicyInfo().getSignPolicyIdentifier().getValue());
                }
            }
            return Set.copyOf(oids);
        });
    }

    /** Política fora do período de assinatura é configuração vencida do serviço: 500. */
    public static void requireInForce(Kind kind, Instant at) {
        SigningPeriod period = load(of(kind)).getSignPolicyInfo().getSignatureValidationPolicy().getSigningPeriod();
        Date when = Date.from(at);
        if (period.getNotBefore() != null && when.before(period.getNotBefore().getDate())) {
            throw new SignerFailure(SignerFailure.Code.INTERNAL);
        }
        if (period.getNotAfter() != null && when.after(period.getNotAfter().getDate())) {
            throw new SignerFailure(SignerFailure.Code.INTERNAL);
        }
    }
}
