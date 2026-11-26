package com.kach0ta.kch;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;

/** Standalone JVM self-test; uses only standard Java security providers. */
public final class CryptoPrimitivesSelfTest {
    private CryptoPrimitivesSelfTest() {}

    public static void main(String[] args) throws Exception {
        testHkdfRfc5869Case1();
        testEcdhAgreementAndEncoding();
        testRejectsWrongCurve();
        System.out.println("PASS: 3 CryptoPrimitives self-tests");
    }

    private static void testHkdfRfc5869Case1() throws Exception {
        byte[] ikm = repeat((byte) 0x0b, 22);
        byte[] salt = hex("000102030405060708090a0b0c");
        byte[] info = hex("f0f1f2f3f4f5f6f7f8f9");
        byte[] expected = hex(
            "3cb25f25faacd57a90434f64d0362f2a" +
            "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
            "34007208d5b887185865"
        );
        byte[] actual = CryptoPrimitives.hkdfSha256(ikm, salt, info, 42);
        check(Arrays.equals(expected, actual), "RFC 5869 test case 1");
    }

    private static void testEcdhAgreementAndEncoding() throws Exception {
        KeyPair alice = CryptoPrimitives.newEphemeralKeyPair();
        KeyPair bob = CryptoPrimitives.newEphemeralKeyPair();
        byte[] salt = hex("00112233445566778899aabbccddeeff");
        byte[] info = "kch:test:session:v1".getBytes("UTF-8");

        byte[] aliceKey = CryptoPrimitives.deriveKey(
            alice.getPrivate(), bob.getPublic(), salt, "kch:test:session:v1", 32);
        byte[] bobKey = CryptoPrimitives.deriveKey(
            bob.getPrivate(), alice.getPublic(), salt, "kch:test:session:v1", 32);
        check(Arrays.equals(aliceKey, bobKey), "ECDH shared key agreement");

        byte[] encoded = CryptoPrimitives.encodePublicKey(alice.getPublic());
        PublicKey decoded = CryptoPrimitives.decodePublicKey(encoded);
        byte[] decodedKey = CryptoPrimitives.deriveKey(
            bob.getPrivate(), decoded, salt, "kch:test:session:v1", 32);
        check(Arrays.equals(aliceKey, decodedKey), "P-256 public key encode/decode");
    }

    private static void testRejectsWrongCurve() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("EC");
        generator.initialize(new java.security.spec.ECGenParameterSpec("secp384r1"));
        KeyPair wrongCurve = generator.generateKeyPair();
        boolean rejected = false;
        try {
            CryptoPrimitives.encodePublicKey(wrongCurve.getPublic());
        } catch (java.security.GeneralSecurityException expected) {
            rejected = true;
        }
        check(rejected, "reject non-P-256 curve");
    }

    private static byte[] repeat(byte value, int count) {
        byte[] result = new byte[count];
        Arrays.fill(result, value);
        return result;
    }

    private static byte[] hex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static void check(boolean ok, String name) {
        if (!ok) throw new AssertionError("FAILED: " + name);
        System.out.println("PASS: " + name);
    }
}
