package com.kach0ta.kch;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Platform-provided cryptographic building blocks for the K.C.H. prototype.
 *
 * This class is NOT a messaging protocol and must not be treated as production
 * E2EE. In particular, it does not authenticate public keys, prevent replay,
 * implement a ratchet, provide forward secrecy across messages, or manage
 * group membership. Those protocol properties must be designed and reviewed
 * before this code is used for real conversations.
 *
 * Uses Android/JCA primitives available on the project's API 23 baseline:
 * ECDH over secp256r1 and HKDF-SHA-256 (RFC 5869).
 */
public final class CryptoPrimitives {
    private static final String CURVE = "secp256r1";
    private static final String HMAC = "HmacSHA256";
    private static final int HASH_BYTES = 32;

    private CryptoPrimitives() {}

    /** Creates an ephemeral ECDH key pair. Keep the private key on this device. */
    public static KeyPair newEphemeralKeyPair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(CURVE));
        return generator.generateKeyPair();
    }

    /** Encodes a public key using the standard X.509 SubjectPublicKeyInfo format. */
    public static byte[] encodePublicKey(PublicKey publicKey) throws GeneralSecurityException {
        if (publicKey == null || !"EC".equalsIgnoreCase(publicKey.getAlgorithm())) {
            throw new GeneralSecurityException("An EC public key is required");
        }
        return publicKey.getEncoded();
    }

    /** Decodes an EC public key. This does NOT authenticate who owns the key. */
    public static PublicKey decodePublicKey(byte[] encoded) throws GeneralSecurityException {
        if (encoded == null || encoded.length == 0 || encoded.length > 1024) {
            throw new GeneralSecurityException("Invalid public key encoding");
        }
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
    }

    /**
     * Derives key material from an ECDH exchange using HKDF-SHA-256.
     * The caller must authenticate the peer public key through a separately
     * designed identity/signature verification protocol before relying on it.
     */
    public static byte[] deriveKey(PrivateKey localPrivate, PublicKey peerPublic,
                                   byte[] salt, String context, int outputBytes)
            throws GeneralSecurityException {
        if (localPrivate == null || peerPublic == null) {
            throw new GeneralSecurityException("ECDH keys are required");
        }
        if (context == null || context.length() == 0) {
            throw new GeneralSecurityException("A non-empty context is required");
        }
        if (outputBytes < 1 || outputBytes > 255 * HASH_BYTES) {
            throw new GeneralSecurityException("Invalid HKDF output length");
        }

        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(localPrivate);
        agreement.doPhase(peerPublic, true);
        byte[] sharedSecret = agreement.generateSecret();
        try {
            return hkdfSha256(sharedSecret, salt,
                    context.getBytes(StandardCharsets.UTF_8), outputBytes);
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
        }
    }

    /** RFC 5869 HKDF using HMAC-SHA-256. */
    public static byte[] hkdfSha256(byte[] inputKeyMaterial, byte[] salt,
                                    byte[] info, int outputBytes)
            throws GeneralSecurityException {
        if (inputKeyMaterial == null || inputKeyMaterial.length == 0) {
            throw new GeneralSecurityException("Input key material is required");
        }
        if (outputBytes < 1 || outputBytes > 255 * HASH_BYTES) {
            throw new GeneralSecurityException("Invalid HKDF output length");
        }

        byte[] actualSalt = (salt == null || salt.length == 0)
                ? new byte[HASH_BYTES] : salt.clone();
        byte[] actualInfo = info == null ? new byte[0] : info;
        byte[] prk = hmac(actualSalt, inputKeyMaterial);
        byte[] result = new byte[outputBytes];
        byte[] previous = new byte[0];
        int offset = 0;
        try {
            for (int counter = 1; offset < outputBytes; counter++) {
                byte[] blockInput = new byte[previous.length + actualInfo.length + 1];
                System.arraycopy(previous, 0, blockInput, 0, previous.length);
                System.arraycopy(actualInfo, 0, blockInput, previous.length, actualInfo.length);
                blockInput[blockInput.length - 1] = (byte) counter;
                byte[] next = hmac(prk, blockInput);
                Arrays.fill(blockInput, (byte) 0);
                if (previous.length > 0) Arrays.fill(previous, (byte) 0);
                previous = next;
                int copy = Math.min(previous.length, outputBytes - offset);
                System.arraycopy(previous, 0, result, offset, copy);
                offset += copy;
            }
            return result;
        } finally {
            Arrays.fill(prk, (byte) 0);
            Arrays.fill(actualSalt, (byte) 0);
            if (previous.length > 0) Arrays.fill(previous, (byte) 0);
        }
    }

    private static byte[] hmac(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(key, HMAC));
        return mac.doFinal(data);
    }
}
