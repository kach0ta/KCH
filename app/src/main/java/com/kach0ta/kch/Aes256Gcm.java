package com.kach0ta.kch;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Device-local AES-256-GCM helper.
 * This key is not a conversation key and must never be sent to the server.
 * End-to-end messaging requires a separate authenticated session protocol.
 */
public final class Aes256Gcm {
    private static final String STORE = "AndroidKeyStore";
    private static final String ALIAS = "kch.local.aes256.v1";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int VERSION = 1;
    private static final int IV_LENGTH = 12;
    private static final int TAG_BITS = 128;

    private Aes256Gcm() {}

    /** Encrypt UTF-8 text. Envelope: version byte, IV length, IV, ciphertext and tag. */
    public static String encrypt(String plaintext, byte[] associatedData)
            throws GeneralSecurityException {
        if (plaintext == null) throw new IllegalArgumentException("plaintext is null");

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey());
        if (associatedData != null) cipher.updateAAD(associatedData);

        byte[] iv = cipher.getIV();
        if (iv == null || iv.length != IV_LENGTH) {
            throw new GeneralSecurityException("Unexpected AES-GCM IV length");
        }
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ByteArrayOutputStream envelope = new ByteArrayOutputStream(2 + iv.length + ciphertext.length);
        envelope.write(VERSION);
        envelope.write(iv.length);
        envelope.write(iv, 0, iv.length);
        envelope.write(ciphertext, 0, ciphertext.length);
        return Base64.encodeToString(envelope.toByteArray(), Base64.NO_WRAP);
    }

    /** Decrypt an envelope produced by encrypt(). The AAD must match exactly. */
    public static String decrypt(String encoded, byte[] associatedData)
            throws GeneralSecurityException {
        if (encoded == null) throw new IllegalArgumentException("envelope is null");

        final byte[] envelope;
        try {
            envelope = Base64.decode(encoded, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("Invalid encrypted envelope", e);
        }

        if (envelope.length < 2 + IV_LENGTH + 16 || (envelope[0] & 0xff) != VERSION) {
            throw new GeneralSecurityException("Unsupported or malformed encrypted envelope");
        }
        int ivLength = envelope[1] & 0xff;
        if (ivLength != IV_LENGTH || envelope.length < 2 + ivLength + 16) {
            throw new GeneralSecurityException("Malformed AES-GCM envelope");
        }

        byte[] iv = new byte[ivLength];
        System.arraycopy(envelope, 2, iv, 0, ivLength);
        byte[] ciphertext = new byte[envelope.length - 2 - ivLength];
        System.arraycopy(envelope, 2 + ivLength, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), new GCMParameterSpec(TAG_BITS, iv));
        if (associatedData != null) cipher.updateAAD(associatedData);
        return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
    }

    private static SecretKey getOrCreateKey() throws GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance(STORE);
        try {
            keyStore.load(null);
            java.security.Key existing = keyStore.getKey(ALIAS, null);
            if (existing instanceof SecretKey) return (SecretKey) existing;
        } catch (java.io.IOException e) {
            throw new GeneralSecurityException("Unable to access Android Keystore", e);
        } catch (java.security.cert.CertificateException e) {
            throw new GeneralSecurityException("Unable to load Android Keystore", e);
        } catch (java.security.UnrecoverableKeyException e) {
            throw new GeneralSecurityException("Unable to recover local encryption key", e);
        }

        KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, STORE);
        generator.init(new KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build());
        return generator.generateKey();
    }
}
