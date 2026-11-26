package com.kach0ta.kch;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * Proof that a device registration request is authorized by its identity key.
 * The account ID is supplied by the authenticated API session and is bound
 * into the signed transcript. This class does not contact or trust a server.
 */
public final class DeviceRegistrationProof {
    public static final int VERSION = 1;
    private static final String PURPOSE = "DEVICE-REGISTRATION-V1";
    private static final int MAX_ID_BYTES = 128;
    private static final int MAX_PUBLIC_KEY_BYTES = 1024;
    private final String accountId;
    private final String deviceId;
    private final byte[] identityPublicKey;
    private final byte[] signature;

    private DeviceRegistrationProof(String accountId, String deviceId,
                                    byte[] identityPublicKey, byte[] signature) {
        this.accountId = accountId;
        this.deviceId = deviceId;
        this.identityPublicKey = identityPublicKey.clone();
        this.signature = signature.clone();
    }

    public static DeviceRegistrationProof create(String accountId, String deviceId)
            throws GeneralSecurityException {
        byte[] identity = DeviceIdentity.getOrCreatePublicKey();
        byte[] payload = canonicalPayload(accountId, deviceId, identity);
        byte[] signature = DeviceIdentity.sign(PURPOSE, payload);
        return new DeviceRegistrationProof(accountId, deviceId, identity, signature);
    }

    public boolean verify() throws GeneralSecurityException {
        return DeviceIdentity.verify(identityPublicKey, PURPOSE,
                canonicalPayload(accountId, deviceId, identityPublicKey), signature);
    }

    public boolean verifyAgainst(byte[] expectedIdentityPublicKey)
            throws GeneralSecurityException {
        if (!java.security.MessageDigest.isEqual(identityPublicKey, expectedIdentityPublicKey)) {
            return false;
        }
        return verify();
    }

    public String getAccountId() { return accountId; }
    public String getDeviceId() { return deviceId; }
    public byte[] getIdentityPublicKey() { return identityPublicKey.clone(); }
    public byte[] getSignature() { return signature.clone(); }

    public static byte[] canonicalPayload(String accountId, String deviceId,
                                          byte[] encodedIdentityPublicKey)
            throws GeneralSecurityException {
        validateId(accountId, "account");
        validateId(deviceId, "device");
        if (encodedIdentityPublicKey == null || encodedIdentityPublicKey.length == 0
                || encodedIdentityPublicKey.length > MAX_PUBLIC_KEY_BYTES) {
            throw new GeneralSecurityException("Invalid device identity public key");
        }
        CryptoPrimitives.decodePublicKey(encodedIdentityPublicKey);
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(bytes);
            out.write("KCH-DEVICE-REGISTRATION".getBytes(StandardCharsets.US_ASCII));
            out.writeByte(0);
            out.writeInt(VERSION);
            writeString(out, accountId);
            writeString(out, deviceId);
            out.writeInt(encodedIdentityPublicKey.length);
            out.write(encodedIdentityPublicKey);
            out.flush();
            return bytes.toByteArray();
        } catch (IOException impossible) {
            throw new GeneralSecurityException("Unable to encode device registration proof", impossible);
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
