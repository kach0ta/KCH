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
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Experimental local store for identity-signed one-time P-256 prekeys.
 *
 * Private key bytes are encrypted at rest with the device-local Android
 * Keystore AES-GCM key. This store does not publish keys, claim them from a
 * server, establish sessions, or provide replay protection / a ratchet.
 */
public final class LocalOneTimePreKeyStore {
    private static final String PREFS = "kch_local_one_time_prekeys_v1";
    private static final String PREFIX = "otpk.";
    private static final String AAD_PREFIX = "KCH-LOCAL-ONE-TIME-PREKEY-PRIVATE-V1:";
    private static final String CURVE = "secp256r1";
    public static final int MAX_POOL_SIZE = 100;

    public static final String STATUS_LOCAL_ONLY = "LOCAL_ONLY";
    public static final String STATUS_PUBLISHED = "PUBLISHED";
    public static final String STATUS_CONSUMED = "CONSUMED";

    private LocalOneTimePreKeyStore() {}

    public static final class StoredOneTimePreKey {
        public final String accountId;
        public final String deviceId;
        public final String keyId;
        public final byte[] publicKeyEncoded;
        public final byte[] signature;
        public final KeyPair keyPair;
        public final String status;

        private StoredOneTimePreKey(String accountId, String deviceId, String keyId,
                                    byte[] publicKeyEncoded, byte[] signature,
                                    KeyPair keyPair, String status) {
            this.accountId = accountId;
            this.deviceId = deviceId;
            this.keyId = keyId;
            this.publicKeyEncoded = publicKeyEncoded.clone();
            this.signature = signature.clone();
            this.keyPair = keyPair;
            this.status = status;
        }
    }

    /** Creates a new random-ID key, or reloads that exact record if ID exists. */
    public static synchronized StoredOneTimePreKey getOrCreate(
            Context context, String accountId, String deviceId, String keyId)
            throws GeneralSecurityException {
        if (context == null) throw new GeneralSecurityException("Context is required");
        validateKeyId(keyId);
        byte[] validationKey = generatePair().getPublic().getEncoded();
        OneTimePreKeyBundle.canonicalPayload(accountId, deviceId, keyId, validationKey);

        SharedPreferences prefs = preferences(context);
        String base = PREFIX + keyId + ".";
        String existingStatus = prefs.getString(base + "status", null);
        if (existingStatus != null) {
            return load(context, accountId, deviceId, keyId);
        }
        boolean partialRecord = prefs.contains(base + "account")
                || prefs.contains(base + "device") || prefs.contains(base + "public")
                || prefs.contains(base + "signature") || prefs.contains(base + "private");
        if (partialRecord) {
            throw new GeneralSecurityException("Incomplete one-time prekey record; refusing overwrite");
        }
        if (countRecords(prefs) >= MAX_POOL_SIZE) {
            throw new GeneralSecurityException("One-time prekey pool is full");
        }

        KeyPair pair = generatePair();
        byte[] publicBytes = CryptoPrimitives.encodePublicKey(pair.getPublic());
        byte[] transcript = OneTimePreKeyBundle.canonicalPayload(
                accountId, deviceId, keyId, publicBytes);
        byte[] signature = DeviceIdentity.sign("ONE-TIME-PREKEY-V1", transcript);
        String encryptedPrivate = encryptPrivate(accountId, deviceId, keyId,
                publicBytes, pair);

        boolean saved = prefs.edit()
                .putString(base + "account", accountId)
                .putString(base + "device", deviceId)
                .putString(base + "public", Base64.encodeToString(publicBytes, Base64.NO_WRAP))
                .putString(base + "signature", Base64.encodeToString(signature, Base64.NO_WRAP))
                .putString(base + "private", encryptedPrivate)
                .putString(base + "status", STATUS_LOCAL_ONLY)
                .commit();
        if (!saved) throw new GeneralSecurityException("Unable to persist one-time prekey");
        return new StoredOneTimePreKey(accountId, deviceId, keyId,
                publicBytes, signature, pair, STATUS_LOCAL_ONLY);
    }

    /** Creates a fresh key with an unpredictable identifier. */
    public static StoredOneTimePreKey createNew(Context context, String accountId,
                                                String deviceId)
            throws GeneralSecurityException {
        return getOrCreate(context, accountId, deviceId,
                "otpk-" + UUID.randomUUID().toString());
    }

    /** Restores a key only when metadata, identity signature and keypair all match. */
    public static synchronized StoredOneTimePreKey load(
            Context context, String accountId, String deviceId, String keyId)
            throws GeneralSecurityException {
        if (context == null) throw new GeneralSecurityException("Context is required");
        validateKeyId(keyId);
        SharedPreferences prefs = preferences(context);
        String base = PREFIX + keyId + ".";
        String storedAccount = prefs.getString(base + "account", null);
        String storedDevice = prefs.getString(base + "device", null);
        String publicB64 = prefs.getString(base + "public", null);
        String signatureB64 = prefs.getString(base + "signature", null);
        String encryptedPrivate = prefs.getString(base + "private", null);
        String status = prefs.getString(base + "status", null);

        if (storedAccount == null || storedDevice == null || publicB64 == null
                || signatureB64 == null || encryptedPrivate == null || status == null
                || !accountId.equals(storedAccount) || !deviceId.equals(storedDevice)
                || !isValidStatus(status)) {
            throw new GeneralSecurityException("Stored one-time prekey metadata is incomplete or mismatched");
        }

        final byte[] publicBytes;
        final byte[] signatureBytes;
        try {
            publicBytes = Base64.decode(publicB64, Base64.NO_WRAP);
            signatureBytes = Base64.decode(signatureB64, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Stored one-time prekey encoding is invalid", e);
        }

        byte[] transcript = OneTimePreKeyBundle.canonicalPayload(
                accountId, deviceId, keyId, publicBytes);
        if (!DeviceIdentity.verify(DeviceIdentity.getOrCreatePublicKey(),
                "ONE-TIME-PREKEY-V1", transcript, signatureBytes)) {
            throw new GeneralSecurityException("Stored one-time prekey identity signature is invalid");
        }

        byte[] aad = associatedData(accountId, deviceId, keyId, publicBytes);
        String privateB64 = Aes256Gcm.decrypt(encryptedPrivate, aad);
        final byte[] privateBytes;
        try {
            privateBytes = Base64.decode(privateB64, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Stored one-time private key encoding is invalid", e);
        }

        try {
            KeyFactory factory = KeyFactory.getInstance("EC");
            java.security.PublicKey publicKey = CryptoPrimitives.decodePublicKey(publicBytes);
            java.security.PrivateKey privateKey =
                    factory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes));
            KeyPair pair = new KeyPair(publicKey, privateKey);
            verifyPair(pair);
            return new StoredOneTimePreKey(accountId, deviceId, keyId,
                    publicBytes, signatureBytes, pair, status);
        } catch (java.security.spec.InvalidKeySpecException e) {
            throw new GeneralSecurityException("Stored one-time private key is invalid", e);
        }
    }

    /** Records successful publication; does not delete the private key. */
    public static synchronized boolean markPublished(Context context, String keyId) {
        return transition(context, keyId, STATUS_LOCAL_ONLY, STATUS_PUBLISHED);
    }

    /** Call only after an authenticated session has safely consumed this key. */
    public static synchronized boolean markConsumed(Context context, String keyId) {
        return transition(context, keyId, STATUS_PUBLISHED, STATUS_CONSUMED);
    }

    /** Deletes only a key explicitly marked consumed after session completion. */
    public static synchronized boolean deleteConsumed(Context context, String keyId) {
        if (context == null || !isValidKeyId(keyId)) return false;
        SharedPreferences prefs = preferences(context);
        String base = PREFIX + keyId + ".";
        if (!STATUS_CONSUMED.equals(prefs.getString(base + "status", null))) return false;
        return prefs.edit().remove(base + "account").remove(base + "device")
                .remove(base + "public").remove(base + "signature")
                .remove(base + "private").remove(base + "status").commit();
    }

    public static synchronized int count(Context context) {
        if (context == null) return 0;
        return countRecords(preferences(context));
    }

    private static boolean transition(Context context, String keyId,
                                      String expected, String next) {
        if (context == null || !isValidKeyId(keyId)) return false;
        SharedPreferences prefs = preferences(context);
        String key = PREFIX + keyId + ".status";
        if (!expected.equals(prefs.getString(key, null))) return false;
        return prefs.edit().putString(key, next).commit();
    }

    private static String encryptPrivate(String accountId, String deviceId, String keyId,
                                         byte[] publicBytes, KeyPair pair)
            throws GeneralSecurityException {
        String privateB64 = Base64.encodeToString(
                pair.getPrivate().getEncoded(), Base64.NO_WRAP);
        return Aes256Gcm.encrypt(privateB64,
                associatedData(accountId, deviceId, keyId, publicBytes));
    }

    private static byte[] associatedData(String accountId, String deviceId,
                                         String keyId, byte[] publicBytes)
            throws GeneralSecurityException {
        byte[] transcript = OneTimePreKeyBundle.canonicalPayload(
                accountId, deviceId, keyId, publicBytes);
        byte[] prefix = AAD_PREFIX.getBytes(StandardCharsets.US_ASCII);
        byte[] result = new byte[prefix.length + transcript.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(transcript, 0, result, prefix.length, transcript.length);
        return result;
    }

    private static void verifyPair(KeyPair pair) throws GeneralSecurityException {
        byte[] challenge = "KCH-ONE-TIME-PREKEY-PAIR-CHECK-V1"
                .getBytes(StandardCharsets.US_ASCII);
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(pair.getPrivate());
        signer.update(challenge);
        byte[] proof = signer.sign();
        Signature verifier = Signature.getInstance("SHA256withECDSA");
        verifier.initVerify(pair.getPublic());
        verifier.update(challenge);
        if (!verifier.verify(proof)) {
            throw new GeneralSecurityException("Stored one-time prekey pair does not match");
        }
    }

    private static KeyPair generatePair() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec(CURVE));
        return generator.generateKeyPair();
    }

    private static SharedPreferences preferences(Context context) {
        return context.getApplicationContext()
                .getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    }

    private static int countRecords(SharedPreferences prefs) {
        int count = 0;
        for (String key : prefs.getAll().keySet()) {
            if (key.startsWith(PREFIX) && key.endsWith(".status")) count++;
        }
        return count;
    }

    private static boolean isValidStatus(String status) {
        return STATUS_LOCAL_ONLY.equals(status) || STATUS_PUBLISHED.equals(status)
                || STATUS_CONSUMED.equals(status);
    }

    private static void validateKeyId(String keyId) throws GeneralSecurityException {
        if (!isValidKeyId(keyId)) throw new GeneralSecurityException("Invalid one-time prekey ID");
    }

    private static boolean isValidKeyId(String keyId) {
        return keyId != null && keyId.matches("[A-Za-z0-9._-]{1,128}");
    }
}
