# abdm-ecdh — Java

ABDM ECDH encryption/decryption for Java.

## Install

### Maven

Add the JitPack repository and dependency to your `pom.xml`:

```xml
<repositories>
  <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
  </repository>
</repositories>

<dependency>
    <groupId>com.github.eka-care</groupId>
    <artifactId>abdm-ecdh</artifactId>
    <version>java-v1.0.0</version>
</dependency>
```

### Gradle

```groovy
repositories {
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.eka-care:abdm-ecdh:java-v1.0.0'
}
```

## Usage

```java
import care.eka.abdmecdh.AbdmEcdh;
import care.eka.abdmecdh.KeyMaterial;
import care.eka.abdmecdh.EncryptionResponse;
import care.eka.abdmecdh.DecryptionResponse;

// Generate key material for one party
KeyMaterial myKeys = AbdmEcdh.generateKeyMaterial();

// Encrypt (sender side)
EncryptionResponse enc = AbdmEcdh.encrypt(
    "sensitive health data",
    myKeys.nonce(),         // senderNonce
    requesterNonce,         // from the other party
    myKeys.privateKey(),    // senderPrivateKey
    requesterPublicKey      // from the other party (uncompressed or X.509 DER)
);

// Decrypt (requester side)
DecryptionResponse dec = AbdmEcdh.decrypt(
    enc.encryptedData(),
    senderNonce,            // from the sender
    myKeys.nonce(),         // requesterNonce
    myKeys.privateKey(),    // requesterPrivateKey
    senderPublicKey         // from the sender
);

System.out.println(dec.decryptedData()); // "sensitive health data"
```

## Key formats

`generateKeyMaterial()` returns four base64-encoded strings:

| Field | Format |
|---|---|
| `privateKey` | BigInteger scalar (Java `BigInteger.toByteArray()` convention) |
| `publicKey` | Uncompressed EC point: `04 \|\| x \|\| y` (65 bytes) |
| `x509PublicKey` | X.509 SubjectPublicKeyInfo DER with explicit BouncyCastle parameters |
| `nonce` | 32 random bytes |

Both `publicKey` and `x509PublicKey` are accepted by `encrypt` and `decrypt`.

## Requirements

- Java 17+
- BouncyCastle `bcprov-jdk18on` 1.80+ (pulled in transitively)
