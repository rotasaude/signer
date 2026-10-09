package rotasaude.signer.engine;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import rotasaude.signer.SignerFailure;

/**
 * prepared_state opaco: versão, tipo, certificado, atributos assinados e PDF preparado,
 * selados com HMAC-SHA256 (chave derivada do SIGNER_TOKEN). Estado adulterado = 400.
 * O mesmo limite por campo vale nos dois sentidos: o encode (no /prepare, antes de o PSC assinar)
 * recusa com 400 o que o decode (no /assemble) recusaria. 32 MiB em base64 ainda cabe no corpo de 48 MB.
 */
public final class PreparedStateCodec {

    private static final int VERSION = 1;
    private static final int MAC_LENGTH = 32;
    static final int MAX_FIELD = 32 * 1024 * 1024;

    private final byte[] key;
    private final int maxField;

    public PreparedStateCodec(String sharedToken) {
        this(sharedToken, MAX_FIELD);
    }

    /** maxField menor só em teste, para não alocar 32 MiB. */
    PreparedStateCodec(String sharedToken, int maxField) {
        this.maxField = maxField;
        this.key = hmac(sharedToken.getBytes(StandardCharsets.UTF_8),
                "rotasaude.signer.prepared_state.v1".getBytes(StandardCharsets.UTF_8));
    }

    public String encode(PreparedSignature prepared) {
        byte[] pdf = prepared.preparedPdf() == null ? new byte[0] : prepared.preparedPdf();
        for (byte[] field : new byte[][] {prepared.certificateDer(), prepared.signedAttributesDer(), pdf}) {
            if (field.length > maxField) throw invalid(); // o /assemble não o aceitaria: falha antes de assinar
        }
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(buffer);
            out.writeByte(VERSION);
            out.writeByte(prepared.kind().ordinal());
            writeField(out, prepared.certificateDer());
            writeField(out, prepared.signedAttributesDer());
            writeField(out, pdf);
            out.flush();
            byte[] body = buffer.toByteArray();
            byte[] sealed = Arrays.copyOf(body, body.length + MAC_LENGTH);
            System.arraycopy(hmac(key, body), 0, sealed, body.length, MAC_LENGTH);
            return Base64.getEncoder().encodeToString(sealed);
        } catch (IOException e) {
            throw new SignerFailure(SignerFailure.Code.INTERNAL);
        }
    }

    public PreparedSignature decode(String encoded) {
        try {
            byte[] sealed = Base64.getDecoder().decode(encoded);
            if (sealed.length <= MAC_LENGTH) throw invalid();
            byte[] body = Arrays.copyOf(sealed, sealed.length - MAC_LENGTH);
            byte[] mac = Arrays.copyOfRange(sealed, body.length, sealed.length);
            if (!MessageDigest.isEqual(mac, hmac(key, body))) throw invalid();
            DataInputStream in = new DataInputStream(new java.io.ByteArrayInputStream(body));
            if (in.readUnsignedByte() != VERSION) throw invalid();
            int kindOrdinal = in.readUnsignedByte();
            if (kindOrdinal >= Kind.values().length) throw invalid();
            Kind kind = Kind.values()[kindOrdinal];
            byte[] certificate = readField(in);
            byte[] attributes = readField(in);
            byte[] pdf = readField(in);
            if (in.available() != 0) throw invalid();
            return new PreparedSignature(kind, certificate, attributes, pdf.length == 0 ? null : pdf);
        } catch (IllegalArgumentException | IOException e) {
            throw invalid();
        }
    }

    private static SignerFailure invalid() {
        return new SignerFailure(SignerFailure.Code.INVALID_REQUEST);
    }

    private static void writeField(DataOutputStream out, byte[] value) throws IOException {
        out.writeInt(value.length);
        out.write(value);
    }

    private byte[] readField(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > maxField || length > in.available()) throw invalid();
        return in.readNBytes(length);
    }

    private static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
