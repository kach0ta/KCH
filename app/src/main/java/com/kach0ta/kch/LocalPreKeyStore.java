package com.kach0ta.kch;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Experimental local persistence for one signed P-256 prekey.
 *
 * The private key is encrypted at rest with the device-local Android Keystore
 * AES-GCM key. It is never returned as text or sent to the API by this class.
 * This is not a hardware-backed ECDH key: API 23 compatibility requires the
 * EC keypair to be generated in the app process before encrypted persistence.
 */
public final class LocalPreKeyStore {
    private static final String PREFS = "kch_local_prekeys_v1";
    private static final String PREFIX = "prekey.";
    private static final String AAD_PREFIX = "KCH-LOCAL-PREKEY-PRIVATE-V1:";
    private static final String CURVE = "secp256r1";

    private LocalPreKeyStore() {}

    public static final class StoredPreKey {
        public final SignedPreKeyBundle bundle;
        public final KeyPair keyPair;

        private StoredPreKey(SignedPreKeyBundle bundle, KeyPair keyPair) {
            this.bundle = bundle;
            this.keyPair = keyPair;
        }
    }

    /**
     * Loads an existing prekey or creates and durably stores a new one.
     * Reusing a key ID with different metadata is rejected; rotation must use
     * a fresh key ID so callers cannot accidentally overwrite a live key.
     */
    public static synchronized StoredPreKey getOrCreate(Context context, String accountId,
                                           String deviceId, String keyId,
                                           long expiresAtEpochSeconds)
            throws GeneralSecurityException {
        if (context == null) throw new GeneralSecurityException("Context is required");
        validateKeyId(keyId);
        SignedPreKeyBundle.canonicalPayload(accountId, deviceId, keyId,
                expiresAtEpochSeconds, placeholderPublicKey());

        SharedPreferences prefs = context.getApplicationContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String base = PREFIX + keyId + ".";
        String storedAccount = prefs.getString(base + "account", null);
        String storedDevice = prefs.getString(base + "device", null);
        String storedPublic = prefs.getString(base + "public", null);
        String storedSignature = prefs.getString(base + "signature", null);
        String storedPrivate = prefs.getString(base + "private", null);
        long storedExpiry = prefs.getLong(base + "expires", -1L);

        boolean anyStored = storedAccount != null || storedDevice != null
                || storedPublic != null || storedSignature != null
                || storedPrivate != null || storedExpiry != -1L;
        if (anyStored) {
            if (storedAccount == null || storedDevice == null || storedPublic == null
                    || storedSignature == null || storedPrivate == null
                    || !accountId.equals(storedAccount) || !deviceId.equals(storedDevice)
                    || storedExpiry != expiresAtEpochSeconds) {
                throw new GeneralSecurityException("Stored prekey metadata mismatch; use a new key ID");
            }
            return restore(context, accountId, deviceId, keyId, storedExpiry,
                    storedPublic, storedSignature, storedPrivate);
        }

        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(CURVE));
        KeyPair pair = generator.generateKeyPair();
        SignedPreKeyBundle bundle = SignedPreKeyBundle.create(accountId, deviceId,
                keyId, expiresAtEpochSeconds, pair.getPublic());
        byte[] aad = aad(accountId, deviceId, keyId, expiresAtEpochSeconds,
                bundle.getPublicKeyEncoded());
        String privateB64 = Base64.encodeToString(pair.getPrivate().getEncoded(), Base64.NO_WRAP);
        String encryptedPrivate = Aes256Gcm.encrypt(privateB64, aad);

        boolean saved = prefs.edit()
                .putString(base + "account", accountId)
                .putString(base + "device", deviceId)
                .putLong(base + "expires", expiresAtEpochSeconds)
                .putString(base + "public", Base64.encodeToString(bundle.getPublicKeyEncoded(), Base64.NO_WRAP))
                .putString(base + "signature", Base64.encodeToString(bundle.getSignature(), Base64.NO_WRAP))
                .putString(base + "private", encryptedPrivate)
                .commit();
        if (!saved) throw new GeneralSecurityException("Unable to persist local prekey");
        return new StoredPreKey(bundle, pair);
    }

    /** Explicitly deletes a local prekey after the protocol confirms it is retired. */
    public static boolean delete(Context context, String keyId) {
        if (context == null || keyId == null || !keyId.matches("[A-Za-z0-9._-]{1,64}")) {
            return false;
        }
        String base = PREFIX + keyId + ".";
        return context.getApplicationContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit().remove(base + "account").remove(base + "device")
                .remove(base + "expires").remove(base + "public")
                .remove(base + "signature").remove(base + "private").commit();
    }

    private static StoredPreKey restore(Context context, String accountId,
                                        String deviceId, String keyId, long expiry,
                                        String publicB64, String signatureB64,
                                        String encryptedPrivate)
            throws GeneralSecurityException {
        final byte[] publicBytes;
        final byte[] signatureBytes;
        try {
            publicBytes = Base64.decode(publicB64, Base64.NO_WRAP);
            signatureBytes = Base64.decode(signatureB64, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Stored prekey encoding is invalid", e);
        }
        byte[] associatedData = aad(accountId, deviceId, keyId, expiry, publicBytes);
        String privateB64 = Aes256Gcm.decrypt(encryptedPrivate, associatedData);
        final byte[] privateBytes;
        try {
            privateBytes = Base64.decode(privateB64, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Stored private prekey encoding is invalid", e);
        }

        java.security.PublicKey publicKey = CryptoPrimitives.decodePublicKey(publicBytes);
        KeyFactory factory = KeyFactory.getInstance("EC");
        java.security.PrivateKey privateKey =
                factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
        KeyPair pair = new KeyPair(publicKey, privateKey);

        byte[] transcript = SignedPreKeyBundle.canonicalPayload(accountId, deviceId,
                keyId, expiry, publicBytes);
        if (!DeviceIdentity.verify(DeviceIdentity.getOrCreatePublicKey(),
                "SIGNED-PREKEY-V1", transcript, signatureBytes)) {
            throw new GeneralSecurityException("Stored prekey identity signature is invalid");
        }
        verifyPair(pair);
        SignedPreKeyBundle bundle = SignedPreKeyBundle.create(accountId, deviceId,
                keyId, expiry, publicKey);
        return new StoredPreKey(bundle, pair);
    }

    private static void verifyPair(KeyPair pair) throws GeneralSecurityException {
        byte[] challenge = "KCH-PREKEY-PAIR-CHECK-V1".getBytes(StandardCharsets.US_ASCII);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(challenge);
        byte[] signature = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(pair.getPublic());
        verifier.update(challenge);
        if (!verifier.verify(signature)) {
            throw new GeneralSecurityException("Stored prekey pair does not match");
        }
    }

    private static byte[] aad(String accountId, String deviceId, String keyId,
                              long expiry, byte[] publicKey)
            throws GeneralSecurityException {
        byte[] transcript = SignedPreKeyBundle.canonicalPayload(accountId, deviceId,
                keyId, expiry, publicKey);
        byte[] prefix = AAD_PREFIX.getBytes(StandardCharsets.US_ASCII);
        byte[] result = new byte[prefix.length + transcript.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(transcript, 0, result, prefix.length, transcript.length);
        return result;
    }

    private static void validateKeyId(String keyId) throws GeneralSecurityException {
        if (keyId == null || !keyId.matches("[A-Za-z0-9._-]{1,64}")) {
            throw new GeneralSecurityException("Invalid prekey ID");
        }
    }

    // Used only to reuse SignedPreKeyBundle's identifier/expiry validation.
    private static byte[] placeholderPublicKey() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(CURVE));
        return CryptoPrimitives.encodePublicKey(generator.generateKeyPair().getPublic());
    }
}
