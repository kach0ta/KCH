package com.kach0ta.kch;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * Canonical, identity-signed public prekey metadata.
 *
 * This is only the authenticated public-key bundle building block. It does
 * not create a session, provide one-time-prekey consumption, prevent replay,
 * or replace a reviewed X3DH/Double Ratchet implementation.
 */
public final class SignedPreKeyBundle {
    public static final int VERSION = 1;
    private static final int MAX_ID_BYTES = 128;
    private static final int MAX_PUBLIC_KEY_BYTES = 1024;
    private static final int MAX_SIGNATURE_BYTES = 128;
    private static final String SIGNATURE_PURPOSE = "SIGNED-PREKEY-V1";

    public final String accountId;
    public final String deviceId;
    public final String keyId;
    public final long expiresAtEpochSeconds;
    private final byte[] publicKey;
    private final byte[] signature;

    private SignedPreKeyBundle(String accountId, String deviceId, String keyId,
                               long expiresAtEpochSeconds, byte[] publicKey,
                               byte[] signature) {
        this.accountId = accountId;
        this.deviceId = deviceId;
        this.keyId = keyId;
        this.expiresAtEpochSeconds = expiresAtEpochSeconds;
        this.publicKey = publicKey.clone();
        this.signature = signature.clone();
    }

    /** Creates a signed bundle. The caller must persist the matching private prekey safely. */
    public static SignedPreKeyBundle create(String accountId, String deviceId,
                                            String keyId, long expiresAtEpochSeconds,
                                            PublicKey prekeyPublic)
            throws GeneralSecurityException {
        validateFields(accountId, deviceId, keyId, expiresAtEpochSeconds);
        byte[] encoded = CryptoPrimitives.encodePublicKey(prekeyPublic);
        byte[] payload = canonicalPayload(accountId, deviceId, keyId,
                expiresAtEpochSeconds, encoded);
        byte[] signed = DeviceIdentity.sign(SIGNATURE_PURPOSE, payload);
        return new SignedPreKeyBundle(accountId, deviceId, keyId,
                expiresAtEpochSeconds, encoded, signed);
    }

    /**
     * Verifies the identity signature and P-256 key encoding.
     * The identity key itself must already be trusted via out-of-band
     * fingerprint verification; a key fetched from the server is not trusted.
     */
    public boolean verify(byte[] trustedIdentityPublicKey, long nowEpochSeconds)
            throws GeneralSecurityException {
        validateFields(accountId, deviceId, keyId, expiresAtEpochSeconds);
        if (expiresAtEpochSeconds <= nowEpochSeconds) return false;
        if (publicKey.length == 0 || publicKey.length > MAX_PUBLIC_KEY_BYTES
                || signature.length == 0 || signature.length > MAX_SIGNATURE_BYTES) {
            throw new GeneralSecurityException("Invalid signed prekey bundle size");
        }
        CryptoPrimitives.decodePublicKey(publicKey);
        byte[] payload = canonicalPayload(accountId, deviceId, keyId,
                expiresAtEpochSeconds, publicKey);
        return DeviceIdentity.verify(trustedIdentityPublicKey,
                SIGNATURE_PURPOSE, payload, signature);
    }

    public byte[] getPublicKeyEncoded() { return publicKey.clone(); }
    public byte[] getSignature() { return signature.clone(); }

    /** Stable, length-prefixed binary transcript; avoids ambiguous string concatenation. */
    public static byte[] canonicalPayload(String accountId, String deviceId,
                                          String keyId, long expiresAtEpochSeconds,
                                          byte[] encodedPublicKey)
            throws GeneralSecurityException {
        validateFields(accountId, deviceId, keyId, expiresAtEpochSeconds);
        if (encodedPublicKey == null || encodedPublicKey.length == 0
                || encodedPublicKey.length > MAX_PUBLIC_KEY_BYTES) {
            throw new GeneralSecurityException("Invalid prekey public key");
        }
        CryptoPrimitives.decodePublicKey(encodedPublicKey);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.write("KCH-SIGNED-PREKEY".getBytes(StandardCharsets.US_ASCII));
            out.writeByte(0);
            out.writeInt(VERSION);
            writeString(out, accountId);
            writeString(out, deviceId);
            writeString(out, keyId);
            out.writeLong(expiresAtEpochSeconds);
            out.writeInt(encodedPublicKey.length);
            out.write(encodedPublicKey);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new GeneralSecurityException("Unable to encode prekey transcript", impossible);
        }
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static void validateFields(String accountId, String deviceId,
                                       String keyId, long expiresAtEpochSeconds)
            throws GeneralSecurityException {
        validateId(accountId, "account");
        validateId(deviceId, "device");
        validateId(keyId, "key");
        if (expiresAtEpochSeconds <= 0) {
            throw new GeneralSecurityException("Invalid prekey expiry");
        }
    }

    private static void validateId(String value, String label)
            throws GeneralSecurityException {
        if (value == null || value.isEmpty()
                || value.getBytes(StandardCharsets.UTF_8).length > MAX_ID_BYTES) {
            throw new GeneralSecurityException("Invalid " + label + " identifier");
        }
    }
}
