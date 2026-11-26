# K.C.H. cryptography prototype tests

These tests cover only the low-level `CryptoPrimitives` helper. They do not validate a messaging protocol or prove end-to-end encryption.

Run from the repository root in Termux or a desktop JDK:

```sh
mkdir -p /tmp/kch-crypto-test
javac -d /tmp/kch-crypto-test \
  app/src/main/java/com/kach0ta/kch/CryptoPrimitives.java \
  tools/crypto-tests/CryptoPrimitivesSelfTest.java
java -cp /tmp/kch-crypto-test com.kach0ta.kch.CryptoPrimitivesSelfTest
```

Expected final line:

```text
PASS: 3 CryptoPrimitives self-tests
```

Tests:
- HKDF-SHA-256 against RFC 5869 test case 1;
- both sides of a P-256 ECDH exchange derive the same key;
- public-key encoding/decoding preserves the exchange;
- non-P-256 EC keys are rejected.

This is a development test harness, not a security audit. Do not use the helper for live messaging until the complete authenticated session protocol is designed, tested and reviewed.
