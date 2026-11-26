package com.kach0ta.kch;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Per-installation device identity key backed by Android Keystore.
 *
 * This class only creates and uses a local signing identity. It does NOT
 * establish contact trust, authenticate server-supplied keys, create
 * messaging sessions, or provide a ratchet. Do not treat a public key
 * downloaded from the API as trusted until its fingerprint is verified.
 */
public final class DeviceIdentity {
    private static final String STORE = "AndroidKeyStore";
    private static final String ALIAS = "kch.device.identity.ecdsa.p256.v1";
    private static final String CURVE = "secp256r1";
    private static final String SIGNATURE = "SHA256withECDSA";
    private static final byte[] PREFIX =
            "KCH-DEVICE-IDENTITY-V1".getBytes(StandardCharsets.UTF_8);
    private static final int MAX_PAYLOAD_BYTES = 1024 * 1024;
    private static final int MAX_SIGNATURE_BYTES = 128;
    private static final int MAX_PUBLIC_KEY_BYTES = 1024;

    private DeviceIdentity() {}

    /**
     * Returns this installation's public identity key in X.509 format.
     * The corresponding private key remains inside Android Keystore.
     */
    public static byte[] getOrCreatePublicKey() throws GeneralSecurityException {
        KeyStore store = loadStore();
        if (!hasAlias(store)) {
            generateIdentityKey();
            store = loadStore();
        }
        java.security.cert.Certificate certificate;
        try {
            certificate = store.getCertificate(ALIAS);
        } catch (java.security.KeyStoreException e) {
            throw new GeneralSecurityException("Unable to read device identity certificate", e);
        }
        if (certificate == null || certificate.getPublicKey() == null) {
            throw new GeneralSecurityException("Device identity public key is unavailable");
        }
        return CryptoPrimitives.encodePublicKey(certificate.getPublicKey());
    }

    /**
     * Signs a bounded payload with explicit domain separation.
     * Use a stable, protocol-defined purpose string, never user-provided text.
     */
    public static byte[] sign(String purpose, byte[] payload)
            throws GeneralSecurityException {
        validatePurposeAndPayload(purpose, payload);
        KeyStore store = loadStore();
        if (!hasAlias(store)) {
            getOrCreatePublicKey();
            store = loadStore();
        }

        PrivateKey privateKey;
        try {
            java.security.Key key = store.getKey(ALIAS, null);
            if (!(key instanceof PrivateKey)) {
                throw new GeneralSecurityException("Device identity private key is unavailable");
            }
            privateKey = (PrivateKey) key;
        } catch (java.security.KeyStoreException
                 | java.security.NoSuchAlgorithmException
                 | java.security.UnrecoverableKeyException e) {
            throw new GeneralSecurityException("Unable to access device identity key", e);
        }

        Signature signer = Signature.getInstance(SIGNATURE);
        signer.initSign(privateKey);
        signer.update(signedBytes(purpose, payload));
        return signer.sign();
    }

    /** Verifies a signature using a supplied P-256 public key. */
    public static boolean verify(byte[] encodedPublicKey, String purpose,
                                 byte[] payload, byte[] signatureBytes)
            throws GeneralSecurityException {
        validatePurposeAndPayload(purpose, payload);
        if (encodedPublicKey == null || encodedPublicKey.length == 0
                || encodedPublicKey.length > MAX_PUBLIC_KEY_BYTES
                || signatureBytes == null || signatureBytes.length == 0
                || signatureBytes.length > MAX_SIGNATURE_BYTES) {
            throw new GeneralSecurityException("Invalid identity verification input");
        }

        PublicKey publicKey = CryptoPrimitives.decodePublicKey(encodedPublicKey);
        Signature verifier = Signature.getInstance(SIGNATURE);
        verifier.initVerify(publicKey);
        verifier.update(signedBytes(purpose, payload));
        return verifier.verify(signatureBytes);
    }

    /** Stable SHA-256 fingerprint of the encoded public identity key. */
    public static String fingerprint(byte[] encodedPublicKey)
            throws GeneralSecurityException {
        if (encodedPublicKey == null || encodedPublicKey.length == 0
                || encodedPublicKey.length > MAX_PUBLIC_KEY_BYTES) {
            throw new GeneralSecurityException("Invalid identity public key");
        }
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(encodedPublicKey);
        StringBuilder out = new StringBuilder(digest.length * 2);
        for (byte value : digest) {
            out.append(String.format(java.util.Locale.US, "%02x", value & 0xff));
        }
        return out.toString();
    }

    public static String publicKeyBase64() throws GeneralSecurityException {
        return Base64.encodeToString(getOrCreatePublicKey(), Base64.NO_WRAP);
    }

    private static void generateIdentityKey() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, STORE);
        generator.initialize(new KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());
        generator.generateKeyPair();
    }

    private static KeyStore loadStore() throws GeneralSecurityException {
        try {
            KeyStore store = KeyStore.getInstance(STORE);
            store.load(null);
            return store;
        } catch (java.io.IOException
                 | java.security.cert.CertificateException
                 | java.security.KeyStoreException
                 | java.security.NoSuchAlgorithmException e) {
            throw new GeneralSecurityException("Unable to load Android Keystore", e);
        }
    }

    private static boolean hasAlias(KeyStore store) throws GeneralSecurityException {
        try {
            return store.containsAlias(ALIAS);
        } catch (java.security.KeyStoreException e) {
            throw new GeneralSecurityException("Unable to inspect device identity key", e);
        }
    }

    private static void validatePurposeAndPayload(String purpose, byte[] payload)
            throws GeneralSecurityException {
        if (purpose == null || purpose.isEmpty() || purpose.length() > 64
                || !purpose.matches("[A-Z0-9._-]+")) {
            throw new GeneralSecurityException("Invalid signature purpose");
        }
        if (payload == null || payload.length == 0 || payload.length > MAX_PAYLOAD_BYTES) {
            throw new GeneralSecurityException("Invalid signature payload");
        }
    }

    private static byte[] signedBytes(String purpose, byte[] payload) {
        byte[] purposeBytes = purpose.getBytes(StandardCharsets.UTF_8);
        ByteBuffer buffer = ByteBuffer.allocate(
                PREFIX.length + 1 + purposeBytes.length + 1 + payload.length);
        buffer.put(PREFIX).put((byte) 0).put(purposeBytes).put((byte) 0).put(payload);
        return buffer.array();
    }
}
