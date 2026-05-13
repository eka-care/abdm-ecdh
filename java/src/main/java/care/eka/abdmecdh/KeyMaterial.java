package care.eka.abdmecdh;

public record KeyMaterial(
    String privateKey,
    String publicKey,
    String x509PublicKey,
    String nonce
) {}
