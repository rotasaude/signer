package rotasaude.signer.devpki;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * AC de teste no formato ICP-Brasil (raiz → intermediária → titular com o otherName
 * 2.16.76.1.3.1 de pessoa física), com LCRs. Usada pelos testes JUnit e, em desenvolvimento,
 * para o api montar o PSC falso. Nunca em produção (Config recusa o boot).
 */
public final class DevPki {

    public record Issued(X509Certificate certificate, PrivateKey privateKey) {}

    private static final ASN1ObjectIdentifier ICP_PF = new ASN1ObjectIdentifier("2.16.76.1.3.1");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String crlBaseUrl;
    private final KeyPair rootKeys;
    private final KeyPair intermediateKeys;
    private final X509Certificate root;
    private final X509Certificate intermediate;
    private final Map<BigInteger, Instant> revoked = new LinkedHashMap<>();

    private DevPki(String crlBaseUrl) throws Exception {
        this.crlBaseUrl = crlBaseUrl.endsWith("/") ? crlBaseUrl : crlBaseUrl + "/";
        Instant now = Instant.now();
        rootKeys = keys();
        intermediateKeys = keys();
        X500Name rootName = new X500Name("CN=AC Raiz de Teste Rota Saude,OU=Teste,O=ICP-Brasil,C=BR");
        X500Name intermediateName = new X500Name("CN=AC Intermediaria de Teste Rota Saude,OU=Teste,O=ICP-Brasil,C=BR");
        root = sign(new JcaX509v3CertificateBuilder(rootName, serial(), Date.from(now.minus(Duration.ofDays(1))),
                        Date.from(now.plus(Duration.ofDays(3650))), rootName, rootKeys.getPublic())
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
                        .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
                        .addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(rootKeys.getPublic())),
                rootKeys.getPrivate());
        intermediate = sign(new JcaX509v3CertificateBuilder(root, serial(), Date.from(now.minus(Duration.ofDays(1))),
                        Date.from(now.plus(Duration.ofDays(1825))), intermediateName, intermediateKeys.getPublic())
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
                        .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
                        .addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(root))
                        .addExtension(Extension.subjectKeyIdentifier, false, new JcaX509ExtensionUtils().createSubjectKeyIdentifier(intermediateKeys.getPublic()))
                        .addExtension(Extension.cRLDistributionPoints, false, distributionPoint("root.crl")),
                rootKeys.getPrivate());
    }

    public static DevPki generate(String crlBaseUrl) {
        try {
            return new DevPki(crlBaseUrl);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public List<X509Certificate> anchors() {
        return List.of(root, intermediate);
    }

    /** e-CPF de teste: CN "NOME:CPF", otherName ICP PF com nascimento e CPF, digitalSignature + nonRepudiation. */
    public Issued issue(String cpf, String name, LocalDate birthDate, Instant notBefore, Instant notAfter) {
        try {
            KeyPair keys = keys();
            String pf = birthDate.format(DateTimeFormatter.ofPattern("ddMMyyyy")) + cpf + "0".repeat(11) + "0".repeat(15) + "0".repeat(6);
            GeneralName otherName = new GeneralName(GeneralName.otherName,
                    new DERSequence(new ASN1EncodableVector() {{
                        add(ICP_PF);
                        add(new DERTaggedObject(true, 0, new DEROctetString(pf.getBytes(StandardCharsets.US_ASCII))));
                    }}));
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(intermediate, serial(), Date.from(notBefore),
                    Date.from(notAfter), new X500Name("CN=" + name + ":" + cpf + ",OU=Teste,O=ICP-Brasil,C=BR"), keys.getPublic())
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation))
                    .addExtension(Extension.subjectAlternativeName, false, new GeneralNames(otherName))
                    .addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(intermediate))
                    .addExtension(Extension.cRLDistributionPoints, false, distributionPoint("intermediate.crl"));
            return new Issued(sign(builder, intermediateKeys.getPrivate()), keys.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public synchronized void revoke(BigInteger serial, Instant when) {
        revoked.put(serial, when);
    }

    /** Desfaz revoke (testes que revogam a AC intermediária compartilhada). */
    public synchronized void unrevoke(BigInteger serial) {
        revoked.remove(serial);
    }

    /** "root.crl" (emitida pela raiz) ou "intermediate.crl" (pela intermediária, com as revogações). */
    public synchronized byte[] crl(String name) {
        Instant now = Instant.now();
        return crl(name, now.minusSeconds(60), now.plus(Duration.ofDays(3650)), null); // AC de teste: LCR longa, para o volume de dev não vencer
    }

    /** LCR com vigência e chave de assinatura à escolha (signingKey null = a da AC emissora); para testes de LCR inautêntica. */
    public synchronized byte[] crl(String name, Instant thisUpdate, Instant nextUpdate, PrivateKey signingKey) {
        try {
            boolean ofRoot = "root.crl".equals(name);
            X509Certificate issuer = ofRoot ? root : intermediate;
            X509v2CRLBuilder builder = new X509v2CRLBuilder(new JcaX509CertificateHolder(issuer).getSubject(), Date.from(thisUpdate));
            builder.setNextUpdate(Date.from(nextUpdate));
            revoked.forEach((serial, when) -> builder.addCRLEntry(serial, Date.from(when), CRLReason.keyCompromise));
            X509CRLHolder holder = builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                    .build(signingKey != null ? signingKey : ofRoot ? rootKeys.getPrivate() : intermediateKeys.getPrivate()));
            return holder.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Escreve anchors.pem, root.pem, intermediate.pem, intermediate.key.pem e as duas LCRs. */
    public void writeTo(Path dir) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("anchors.pem"), pem(root) + pem(intermediate));
        Files.writeString(dir.resolve("root.pem"), pem(root));
        Files.writeString(dir.resolve("intermediate.pem"), pem(intermediate));
        Files.writeString(dir.resolve("intermediate.key.pem"), pem(intermediateKeys.getPrivate()));
        Files.write(dir.resolve("root.crl"), crl("root.crl"));
        Files.write(dir.resolve("intermediate.crl"), crl("intermediate.crl"));
        openForDevApi(dir);
    }

    /**
     * Só dev: o volume é compartilhado com o api (outro uid), cujo PSC falso lê a chave da intermediária
     * e reescreve as LCRs para testar revogação. Diretório 0777 e LCRs 0666; sem POSIX, ignora. Cada
     * caminho é tentado sozinho e falha não derruba o boot: se o api trocou a LCR (o arquivo passa a ser
     * do uid dele), o chmod dá AccessDeniedException e o signer segue — a LCR dele já é legível.
     */
    static void openForDevApi(Path dir) {
        openForDevApi(dir, Files::setPosixFilePermissions);
    }

    /** Ponto de troca para teste: quem aplica as permissões. */
    interface PermissionSetter {
        void apply(Path path, Set<PosixFilePermission> permissions) throws IOException;
    }

    static void openForDevApi(Path dir, PermissionSetter setter) {
        relax(setter, dir, "rwxrwxrwx");
        for (String crl : List.of("root.crl", "intermediate.crl")) {
            Path file = dir.resolve(crl);
            if (Files.exists(file)) relax(setter, file, "rw-rw-rw-");
        }
    }

    private static void relax(PermissionSetter setter, Path path, String permissions) {
        try {
            setter.apply(path, PosixFilePermissions.fromString(permissions));
        } catch (UnsupportedOperationException | IOException ignored) {
            // sem POSIX, ou o caminho é de outro uid (o api reescreveu a LCR): segue o boot
        }
    }

    /** Uso: DevPki <dir> <crlBaseUrl>. Não sobrescreve: com anchors.pem no diretório, não faz nada. */
    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("uso: DevPki <dir> <crlBaseUrl>");
            System.exit(2);
        }
        Path dir = Path.of(args[0]);
        if (Files.exists(dir.resolve("anchors.pem"))) {
            openForDevApi(dir); // volumes criados antes desta regra ganham as permissões no próximo boot
            return;
        }
        generate(args[1]).writeTo(dir);
    }

    private CRLDistPoint distributionPoint(String file) {
        DistributionPoint point = new DistributionPoint(new DistributionPointName(
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlBaseUrl + file))), null, null);
        return new CRLDistPoint(new DistributionPoint[] {point});
    }

    private static KeyPair keys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, RANDOM);
        return generator.generateKeyPair();
    }

    private static BigInteger serial() {
        return new BigInteger(64, RANDOM).abs().add(BigInteger.ONE);
    }

    private static X509Certificate sign(X509v3CertificateBuilder builder, PrivateKey key) throws Exception {
        return new JcaX509CertificateConverter().getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(key)));
    }

    private static String pem(Object object) throws IOException {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
            writer.writeObject(object instanceof PrivateKey key ? new org.bouncycastle.openssl.jcajce.JcaPKCS8Generator(key, null) : object);
        }
        return out.toString();
    }
}
