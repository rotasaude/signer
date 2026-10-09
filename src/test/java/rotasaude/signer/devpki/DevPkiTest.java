package rotasaude.signer.devpki;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.junit.jupiter.api.Test;
import rotasaude.signer.SignerFailure;
import rotasaude.signer.engine.Chain;
import rotasaude.signer.support.TestPki;

class DevPkiTest {

    private static final TestPki PKI = TestPki.get();

    @Test
    void issuesAnIcpBrasilNaturalPersonCertificate() {
        X509Certificate certificate = PKI.professional().certificate();
        BasicCertificate basic = new BasicCertificate(certificate);

        assertTrue(basic.hasCertificatePF());
        assertEquals(TestPki.CPF, basic.getICPBRCertificatePF().getCPF());
        assertTrue(certificate.getKeyUsage()[0] && certificate.getKeyUsage()[1], "digitalSignature + nonRepudiation");
    }

    @Test
    void chainResolvesThroughTheConfiguredAnchors() {
        List<X509Certificate> chain = Chain.of(PKI.professional().certificate());
        assertEquals(3, chain.size());
        assertEquals(PKI.pki.anchors().get(0), chain.get(2));
    }

    @Test
    void certificateFromAnUnknownAuthorityHasNoChain() {
        SignerFailure failure = assertThrows(SignerFailure.class, () -> Chain.of(TestPki.untrustedProfessional().certificate()));
        assertEquals(SignerFailure.Code.INVALID_CERTIFICATE, failure.code);
    }

    @Test
    void mainWritesTheFilesOnceAndNeverOverwrites() throws Exception {
        Path dir = Files.createTempDirectory("dev-pki");
        DevPki.main(new String[] {dir.toString(), "http://signer:8090/dev-pki/"});
        String anchors = Files.readString(dir.resolve("anchors.pem"));
        DevPki.main(new String[] {dir.toString(), "http://signer:8090/dev-pki/"});

        try (Stream<Path> files = Files.list(dir)) {
            assertEquals(Set.of("anchors.pem", "root.pem", "intermediate.pem", "intermediate.key.pem", "root.crl", "intermediate.crl"),
                    files.map(p -> p.getFileName().toString()).collect(Collectors.toSet()));
        }
        assertEquals(anchors, Files.readString(dir.resolve("anchors.pem")));
    }

    @Test
    void writeToLetsAnotherUidRewriteTheCrls(@org.junit.jupiter.api.io.TempDir Path dir) throws Exception {
        PKI.pki.writeTo(dir);
        if (!java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) return;

        assertEquals("rwxrwxrwx", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
        for (String crl : List.of("root.crl", "intermediate.crl")) {
            assertEquals("rw-rw-rw-", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve(crl))));
        }

        Files.setPosixFilePermissions(dir, java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        DevPki.main(new String[] {dir.toString(), "http://signer:8090/dev-pki/"});
        assertEquals("rwxrwxrwx", java.nio.file.attribute.PosixFilePermissions.toString(Files.getPosixFilePermissions(dir)));
    }
}
