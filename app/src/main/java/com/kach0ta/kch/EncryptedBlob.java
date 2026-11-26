package com.kach0ta.kch;

import android.util.Base64;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Authenticated encryption for binary blobs (avatars and attachments).
 *
 * This is a low-level AES-256-GCM building block, NOT an E2EE protocol.
 * The 32-byte content key must be freshly generated for each blob and
 * delivered to authorized devices only through an authenticated E2EE session.
 * Never upload the content key or persist it beside the ciphertext.
 */
public final class EncryptedBlob {
    private static final byte VERSION = 1;
    private static final int KEY_BYTES = 32;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private EncryptedBlob() {}

    /** Creates a fresh random 256-bit content key. Generate one per blob. */
    public static byte[] newContentKey() {
        byte[] key = new byte[KEY_BYTES];
        RANDOM.nextBytes(key);
        return key;
    }

    /**
     * Encrypts arbitrary binary data. context must be a stable, non-secret
     * binding such as "kch:avatar:<user-id>:v1" or
     * "kch:attachment:<conversation-id>:<attachment-id>:v1".
     */
    public static String encrypt(byte[] plaintext, byte[] contentKey, String context)
            throws GeneralSecurityException {
        validate(plaintext, contentKey, context);
        byte[] nonce = new byte[NONCE_BYTES];
        RANDOM.nextBytes(nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE,
                new SecretKeySpec(contentKey, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
        byte[] encrypted = cipher.doFinal(plaintext);

        ByteBuffer envelope = ByteBuffer.allocate(1 + NONCE_BYTES + encrypted.length);
        envelope.put(VERSION).put(nonce).put(encrypted);
        return Base64.encodeToString(envelope.array(), Base64.NO_WRAP);
    }

    /** Authentication failure (wrong key, context, or modified data) throws. */
    public static byte[] decrypt(String encoded, byte[] contentKey, String context)
            throws GeneralSecurityException {
        if (encoded == null) throw new GeneralSecurityException("Missing encrypted blob");
        validate(new byte[0], contentKey, context);
        final byte[] envelope;
        try {
            envelope = Base64.decode(encoded, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Malformed encrypted blob", e);
        }
        if (envelope.length < 1 + NONCE_BYTES + 16 || envelope[0] != VERSION) {
            throw new GeneralSecurityException("Unsupported or truncated encrypted blob");
        }

        byte[] nonce = new byte[NONCE_BYTES];
        System.arraycopy(envelope, 1, nonce, 0, NONCE_BYTES);
        byte[] ciphertext = new byte[envelope.length - 1 - NONCE_BYTES];
        System.arraycopy(envelope, 1 + NONCE_BYTES, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(contentKey, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(ciphertext);
    }

    private static void validate(byte[] data, byte[] key, String context)
            throws GeneralSecurityException {
        if (data == null) throw new GeneralSecurityException("Missing data");
        if (key == null || key.length != KEY_BYTES) {
            throw new GeneralSecurityException("Content key must be 32 bytes");
        }
        if (context == null || context.isEmpty()) {
            throw new GeneralSecurityException("A non-empty encryption context is required");
        }
    }
}
