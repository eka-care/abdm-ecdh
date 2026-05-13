package care.eka.abdmecdh;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ECPoint;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.HKDFParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class AbdmEcdh {

    private static final BigInteger CURVE_P  = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED", 16);
    private static final BigInteger CURVE_A  = new BigInteger("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144", 16);
    private static final BigInteger CURVE_B  = new BigInteger("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864", 16);
    private static final BigInteger CURVE_N  = new BigInteger("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16);
    private static final BigInteger CURVE_GX = new BigInteger("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A", 16);
    private static final BigInteger CURVE_GY = new BigInteger("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16);
    private static final BigInteger COFACTOR = BigInteger.valueOf(8);

    private static final ECCurve CURVE;
    private static final ECDomainParameters DOMAIN_PARAMS;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    static {
        CURVE = new ECCurve.Fp(CURVE_P, CURVE_A, CURVE_B, CURVE_N, COFACTOR);
        ECPoint G = CURVE.createPoint(CURVE_GX, CURVE_GY);
        DOMAIN_PARAMS = new ECDomainParameters(CURVE, G, CURVE_N, COFACTOR);
    }

    public static KeyMaterial generateKeyMaterial() {
        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(DOMAIN_PARAMS, SECURE_RANDOM));
        AsymmetricCipherKeyPair pair = gen.generateKeyPair();

        ECPrivateKeyParameters priv = (ECPrivateKeyParameters) pair.getPrivate();
        ECPublicKeyParameters pub   = (ECPublicKeyParameters)  pair.getPublic();

        byte[] privBytes  = priv.getD().toByteArray();
        byte[] pubBytes   = pub.getQ().getEncoded(false);
        byte[] x509Bytes  = buildX509PublicKey(pub.getQ());
        byte[] nonceBytes = new byte[32];
        SECURE_RANDOM.nextBytes(nonceBytes);

        Base64.Encoder enc = Base64.getEncoder();
        return new KeyMaterial(
            enc.encodeToString(privBytes),
            enc.encodeToString(pubBytes),
            enc.encodeToString(x509Bytes),
            enc.encodeToString(nonceBytes)
        );
    }

    public static EncryptionResponse encrypt(
        String stringToEncrypt,
        String senderNonce,
        String requesterNonce,
        String senderPrivateKey,
        String requesterPublicKey
    ) {
        byte[][] ivAndSalt  = deriveIvAndSalt(senderNonce, requesterNonce);
        byte[] sharedSecret = computeSharedSecret(senderPrivateKey, requesterPublicKey);
        byte[] aesKey       = deriveAesKey(sharedSecret, ivAndSalt[1]);
        byte[] ciphertext   = aesGcmEncrypt(aesKey, ivAndSalt[0],
                                stringToEncrypt.getBytes(StandardCharsets.UTF_8));
        return new EncryptionResponse(Base64.getEncoder().encodeToString(ciphertext));
    }

    public static DecryptionResponse decrypt(
        String encryptedData,
        String senderNonce,
        String requesterNonce,
        String requesterPrivateKey,
        String senderPublicKey
    ) {
        encryptedData  = sanitizeBase64(encryptedData);
        senderNonce    = sanitizeBase64(senderNonce);
        requesterNonce = sanitizeBase64(requesterNonce);

        byte[][] ivAndSalt  = deriveIvAndSalt(senderNonce, requesterNonce);
        byte[] sharedSecret = computeSharedSecret(requesterPrivateKey, senderPublicKey);
        byte[] aesKey       = deriveAesKey(sharedSecret, ivAndSalt[1]);
        byte[] plaintext    = aesGcmDecrypt(aesKey, ivAndSalt[0],
                                Base64.getDecoder().decode(encryptedData));
        return new DecryptionResponse(new String(plaintext, StandardCharsets.UTF_8));
    }

    static String sanitizeBase64(String s) {
        return s.replace("\\u002B", "+").replace("\\u002F", "/").replace("\\u003D", "=");
    }

    static byte[] xorBytes(byte[] a, byte[] b) {
        if (a.length != b.length)
            throw new IllegalArgumentException(
                "xorBytes: length mismatch (" + a.length + " vs " + b.length + ")");
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) result[i] = (byte) (a[i] ^ b[i]);
        return result;
    }

    static byte[][] deriveIvAndSalt(String senderNonce, String requesterNonce) {
        if (senderNonce == null || senderNonce.isEmpty())
            throw new IllegalArgumentException("sender nonce is empty");
        if (requesterNonce == null || requesterNonce.isEmpty())
            throw new IllegalArgumentException("requester nonce is empty");
        byte[] xored = xorBytes(
            Base64.getDecoder().decode(senderNonce),
            Base64.getDecoder().decode(requesterNonce)
        );
        if (xored.length < 20)
            throw new IllegalArgumentException(
                "XORed nonce too short (" + xored.length + " bytes), need at least 20");
        byte[] salt = new byte[20];
        byte[] iv   = new byte[12];
        System.arraycopy(xored, 0, salt, 0, 20);
        System.arraycopy(xored, xored.length - 12, iv, 0, 12);
        return new byte[][]{iv, salt};
    }

    static byte[] computeSharedSecret(String b64PrivateKey, String b64PublicKey) {
        b64PrivateKey = sanitizeBase64(b64PrivateKey);
        b64PublicKey  = sanitizeBase64(b64PublicKey);

        BigInteger d = new BigInteger(Base64.getDecoder().decode(b64PrivateKey));

        ECPoint point;
        if (b64PublicKey.length() == 88) {
            point = CURVE.decodePoint(Base64.getDecoder().decode(b64PublicKey));
        } else {
            point = parseX509PublicKey(Base64.getDecoder().decode(b64PublicKey));
        }

        ECPoint sharedPoint = point.multiply(d).normalize();
        return toBytes32(sharedPoint.getAffineXCoord().toBigInteger());
    }

    static byte[] deriveAesKey(byte[] sharedSecret, byte[] salt) {
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(new HKDFParameters(sharedSecret, salt, new byte[0]));
        byte[] key = new byte[32];
        hkdf.generateBytes(key, 0, 32);
        return key;
    }

    static byte[] aesGcmEncrypt(byte[] key, byte[] iv, byte[] plaintext) {
        try {
            GCMModeCipher cipher = GCMBlockCipher.newInstance(new AESEngine());
            cipher.init(true, new AEADParameters(new KeyParameter(key), 128, iv));
            byte[] out = new byte[cipher.getOutputSize(plaintext.length)];
            int len = cipher.processBytes(plaintext, 0, plaintext.length, out, 0);
            cipher.doFinal(out, len);
            return out;
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryption failed", e);
        }
    }

    static byte[] aesGcmDecrypt(byte[] key, byte[] iv, byte[] ciphertext) {
        try {
            GCMModeCipher cipher = GCMBlockCipher.newInstance(new AESEngine());
            cipher.init(false, new AEADParameters(new KeyParameter(key), 128, iv));
            byte[] out = new byte[cipher.getOutputSize(ciphertext.length)];
            int len = cipher.processBytes(ciphertext, 0, ciphertext.length, out, 0);
            cipher.doFinal(out, len);
            return out;
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decryption failed", e);
        }
    }

    private static byte[] buildX509PublicKey(ECPoint point) {
        try {
            X9ECParameters ecP = new X9ECParameters(
                CURVE,
                new X9ECPoint(DOMAIN_PARAMS.getG(), false),
                DOMAIN_PARAMS.getN(),
                COFACTOR,
                null
            );
            X962Parameters params = new X962Parameters(ecP);
            AlgorithmIdentifier algId = new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey, params
            );
            byte[] pointBytes = point.getEncoded(false);
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, pointBytes);
            return spki.getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build X.509 public key", e);
        }
    }

    private static byte[] toBytes32(BigInteger n) {
        byte[] b = n.toByteArray();
        if (b.length == 32) return b;
        if (b.length > 32) {
            byte[] r = new byte[32];
            System.arraycopy(b, b.length - 32, r, 0, 32);
            return r;
        }
        byte[] r = new byte[32];
        System.arraycopy(b, 0, r, 32 - b.length, b.length);
        return r;
    }

    private static ECPoint parseX509PublicKey(byte[] der) {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(der);
            byte[] pointBytes = spki.getPublicKeyData().getBytes();
            return CURVE.decodePoint(pointBytes);
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse X.509 public key", e);
        }
    }
}
