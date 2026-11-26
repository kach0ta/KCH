package com.kach0ta.kch;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * Identity-signed public one-time prekey metadata.
 *
 * This authenticates one public prekey record only. It does not implement
 * server-side atomic claiming, private-key lifecycle, a session handshake,
 * replay protection, or a messaging ratchet.
 */
public final class OneTimePreKeyBundle {
    public static final int VERSION = 1;
    private static final int MAX_ID_BYTES = 128;
    private static final int MAX_PUBLIC_KEY_BYTES = 1024;
    private static final int MAX_SIGNATURE_BYTES = 128;
    private static final String SIGNATURE_PURPOSE = "ONE-TIME-PREKEY-V1";

    public final String accountId;
    public final String deviceId;
    public final String keyId;
    private final byte[] publicKey;
    private final byte[] signature;

    private OneTimePreKeyBundle(String accountId, String deviceId, String keyId,
                                byte[] publicKey, byte[] signature) {
        this.accountId = accountId;
        this.deviceId = deviceId;
        this.keyId = keyId;
        this.publicKey = publicKey.clone();
        this.signature = signature.clone();
    }

    /** Creates a signed public bundle. The matching private key must stay local. */
    public static OneTimePreKeyBundle create(String accountId, String deviceId,
                                             String keyId, PublicKey prekeyPublic)
            throws GeneralSecurityException {
        byte[] encoded = CryptoPrimitives.encodePublicKey(prekeyPublic);
        byte[] transcript = canonicalPayload(accountId, deviceId, keyId, encoded);
        byte[] signed = DeviceIdentity.sign(SIGNATURE_PURPOSE, transcript);
        return new OneTimePreKeyBundle(accountId, deviceId, keyId, encoded, signed);
    }

    /**
     * Verifies the bundle against an already trusted device identity key.
     * A public identity key received from the server is not trusted by itself.
     */
    public boolean verify(byte[] trustedIdentityPublicKey)
            throws GeneralSecurityException {
        byte[] transcript = canonicalPayload(accountId, deviceId, keyId, publicKey);
        if (signature.length == 0 || signature.length > MAX_SIGNATURE_BYTES) {
            throw new GeneralSecurityException("Invalid one-time prekey signature size");
        }
        return DeviceIdentity.verify(trustedIdentityPublicKey,
                SIGNATURE_PURPOSE, transcript, signature);
    }

    public byte[] getPublicKeyEncoded() { return publicKey.clone(); }
    public byte[] getSignature() { return signature.clone(); }

    /** Canonical length-prefixed transcript, including a distinct domain/version. */
    public static byte[] canonicalPayload(String accountId, String deviceId,
                                          String keyId, byte[] encodedPublicKey)
            throws GeneralSecurityException {
        validateId(accountId, "account");
        validateId(deviceId, "device");
        validateId(keyId, "key");
        if (encodedPublicKey == null || encodedPublicKey.length == 0
                || encodedPublicKey.length > MAX_PUBLIC_KEY_BYTES) {
            throw new GeneralSecurityException("Invalid one-time prekey public key");
        }
        CryptoPrimitives.decodePublicKey(encodedPublicKey);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.write("KCH-ONE-TIME-PREKEY".getBytes(StandardCharsets.US_ASCII));
            out.writeByte(0);
            out.writeInt(VERSION);
            writeString(out, accountId);
            writeString(out, deviceId);
            writeString(out, keyId);
            out.writeInt(encodedPublicKey.length);
            out.write(encodedPublicKey);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new GeneralSecurityException("Unable to encode one-time prekey transcript", impossible);
        }
    }

    private static void writeString(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }

    private static void validateId(String value, String label)
            throws GeneralSecurityException {
        if (value == null || value.isEmpty()
                || value.getBytes(StandardCharsets.UTF_8).length > MAX_ID_BYTES) {
            throw new GeneralSecurityException("Invalid " + label + " identifier");
        }
    }
}
