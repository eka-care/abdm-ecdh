package care.eka.abdmecdh;

import org.junit.jupiter.api.Test;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class AbdmEcdhTest {

    static final String REQUESTER_PRIVATE_KEY = "Dnh316gsSfP+0kiNmEgsIekLsY6BQr7b++3rHQ8otAI=";
    static final String REQUESTER_PUBLIC_KEY  = "BBbWU1fw1y1ErdKasIoQKKAWzq3N9ARcrukg7b1MpD3RHi9ofFAFhyIwMIA5p+iMCcLHkzQRoEFvCpNET1+tFtQ=";
    static final String REQUESTER_NONCE       = "5mLKfBzxPw5+xVgxHu/iG+mzw+xIVN1dSFDrqB/KkIE=";
    static final String SENDER_PRIVATE_KEY    = "BJig2akHxYJKjA/uyUSzVris72DsOt95vVaG2ZzGSDE=";
    static final String SENDER_PUBLIC_KEY     = "BDWu6EFsroAUi8lnWZmLZCDZT7XbpsdEC7eeEtNnseHkDKa0igaRxDQOKro7KBaivUiTxdfvRK0mVlVgWGyZo98=";
    static final String SENDER_NONCE          = "IEEtSc15HpLboL/kjBhu+K2Hqro/aoTh9HAgXA5JwMM=";

    @Test
    void testGenerateKeyMaterialFields() {
        KeyMaterial km = AbdmEcdh.generateKeyMaterial();
        assertNotNull(km.privateKey());
        assertNotNull(km.publicKey());
        assertNotNull(km.x509PublicKey());
        assertNotNull(km.nonce());
        assertDoesNotThrow(() -> Base64.getDecoder().decode(km.privateKey()));
        assertDoesNotThrow(() -> Base64.getDecoder().decode(km.publicKey()));
        assertDoesNotThrow(() -> Base64.getDecoder().decode(km.x509PublicKey()));
        assertDoesNotThrow(() -> Base64.getDecoder().decode(km.nonce()));
    }

    @Test
    void testGeneratedPublicKeyOnCurve() {
        KeyMaterial km = AbdmEcdh.generateKeyMaterial();
        byte[] pubBytes = Base64.getDecoder().decode(km.publicKey());
        assertEquals(65, pubBytes.length);
        assertEquals(0x04, pubBytes[0] & 0xFF);
    }

    @Test
    void testSanitizeBase64() {
        assertEquals("A+B/C=", AbdmEcdh.sanitizeBase64("A\\u002BB\\u002FC\\u003D"));
        assertEquals("unchanged", AbdmEcdh.sanitizeBase64("unchanged"));
    }

    @Test
    void testXorBytesMismatch() {
        assertThrows(IllegalArgumentException.class, () ->
            AbdmEcdh.xorBytes(new byte[]{1}, new byte[]{1, 2})
        );
    }

    @Test
    void testDeriveIvAndSaltLengths() {
        byte[][] ivAndSalt = AbdmEcdh.deriveIvAndSalt(SENDER_NONCE, REQUESTER_NONCE);
        assertEquals(12, ivAndSalt[0].length);
        assertEquals(20, ivAndSalt[1].length);
    }

    @Test
    void testRoundTrip() {
        KeyMaterial sender    = AbdmEcdh.generateKeyMaterial();
        KeyMaterial requester = AbdmEcdh.generateKeyMaterial();
        String original = "The secret is safe";

        EncryptionResponse enc = AbdmEcdh.encrypt(
            original, sender.nonce(), requester.nonce(),
            sender.privateKey(), requester.publicKey()
        );
        DecryptionResponse dec = AbdmEcdh.decrypt(
            enc.encryptedData(), sender.nonce(), requester.nonce(),
            requester.privateKey(), sender.publicKey()
        );
        assertEquals(original, dec.decryptedData());
    }

    @Test
    void testEncryptDecryptWithStaticKeys() {
        String plaintext = "";
        EncryptionResponse enc = AbdmEcdh.encrypt(
            plaintext, SENDER_NONCE, REQUESTER_NONCE,
            SENDER_PRIVATE_KEY, REQUESTER_PUBLIC_KEY
        );
        DecryptionResponse dec = AbdmEcdh.decrypt(
            enc.encryptedData(), SENDER_NONCE, REQUESTER_NONCE,
            REQUESTER_PRIVATE_KEY, SENDER_PUBLIC_KEY
        );
        assertEquals(plaintext, dec.decryptedData());
    }

    @Test
    void testEncryptWithX509PublicKey() {
        KeyMaterial requester = AbdmEcdh.generateKeyMaterial();
        String original = "test x509 path";

        EncryptionResponse enc = AbdmEcdh.encrypt(
            original, SENDER_NONCE, requester.nonce(),
            SENDER_PRIVATE_KEY, requester.x509PublicKey()
        );
        DecryptionResponse dec = AbdmEcdh.decrypt(
            enc.encryptedData(), SENDER_NONCE, requester.nonce(),
            requester.privateKey(), SENDER_PUBLIC_KEY
        );
        assertEquals(original, dec.decryptedData());
    }

    @Test
    void testXorBytesKnown() {
        byte[] result = AbdmEcdh.xorBytes(new byte[]{(byte) 0xFF, 0x00}, new byte[]{0x0F, (byte) 0xF0});
        assertArrayEquals(new byte[]{(byte) 0xF0, (byte) 0xF0}, result);
    }
}
