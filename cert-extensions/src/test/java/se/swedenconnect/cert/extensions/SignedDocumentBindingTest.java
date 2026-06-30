/*
 * Copyright (c) 2026.  Sweden Connect
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.swedenconnect.cert.extensions;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link SignedDocumentBinding}.
 */
class SignedDocumentBindingTest {

  private static final byte[] HASH = new byte[] {
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
  };

  /**
   * SHA-256 digest algorithm identifier with absent parameters, per RFC 5754.
   * Built from the OID constant rather than a name finder so the expected
   * encoding is deterministic and spec-correct.
   */
  private static final AlgorithmIdentifier SHA256 =
      new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);

  @Test
  void oidHasExpectedValue() {
    // id-pe 37  ==  1.3.6.1.5.5.7.1.37
    assertEquals("1.3.6.1.5.5.7.1.37", SignedDocumentBinding.OID.getId());
  }

  @Test
  void roundTripWithBindingType() throws IOException {
    final SignedDocumentBinding original = new SignedDocumentBinding(HASH, SHA256, "cades");

    final byte[] encoded = original.getEncoded("DER");
    final SignedDocumentBinding decoded = SignedDocumentBinding.getInstance(encoded);

    assertArrayEquals(HASH, decoded.getDataTbsHash());
    assertHashAlgIsSha256(decoded.getHashAlg());
    assertEquals("cades", decoded.getBindingType());

    // Encoding must be stable across a decode/re-encode cycle.
    assertArrayEquals(encoded, decoded.getEncoded("DER"));

    // The optional field is present, so the SEQUENCE has three elements.
    assertEquals(3, ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoded)).size());
  }

  @Test
  void toStringTest() {
    final SignedDocumentBinding binding = new SignedDocumentBinding(HASH, SHA256, "cose");
    assertEquals("SignedDocumentBinding [dataTbsHash=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20, hashAlg=SHA-256, bindingType=cose]", binding.toString());
  }

  @Test
  void roundTripWithoutBindingType() throws IOException {
    final SignedDocumentBinding original = new SignedDocumentBinding(HASH, SHA256, null);

    final byte[] encoded = original.getEncoded("DER");
    final SignedDocumentBinding decoded = SignedDocumentBinding.getInstance(encoded);

    assertArrayEquals(HASH, decoded.getDataTbsHash());
    assertHashAlgIsSha256(decoded.getHashAlg());
    assertNull(decoded.getBindingType(), "absent bindingType must decode to null");

    assertArrayEquals(encoded, decoded.getEncoded("DER"));

    // The optional field is omitted, so the SEQUENCE has exactly two elements.
    assertEquals(2, ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoded)).size());
  }

  /**
   * Known-answer test: pins the exact DER against the ASN.1 module definition,
   * not just round-trip self-consistency. Verifies field order, tags, and the
   * absent-parameters encoding of the SHA-256 AlgorithmIdentifier in one shot.
   */
  @Test
  void knownAnswerEncoding() throws IOException {
    final SignedDocumentBinding binding = new SignedDocumentBinding(HASH, SHA256, null);

    final String expected =
        "302f"                                                                 // SEQUENCE (47 bytes)
      + "0420" + "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" // OCTET STRING (hash)
      + "300b0609608648016503040201";                                          // AlgorithmIdentifier { id-sha256 }

    assertEquals(expected, Hex.toHexString(binding.getEncoded("DER")));
  }

  @Test
  void getInstanceReturnsSameInstanceForSignedDocumentBinding() {
    final SignedDocumentBinding original = new SignedDocumentBinding(HASH, SHA256, "xades");
    assertSame(original, SignedDocumentBinding.getInstance(original));
  }

  @Test
  void getInstanceAcceptsAsn1Sequence() {
    final SignedDocumentBinding original = new SignedDocumentBinding(HASH, SHA256, "jws");
    final ASN1Primitive seq = original.toASN1Primitive();
    final SignedDocumentBinding decoded = SignedDocumentBinding.getInstance(seq);
    assertEquals("jws", decoded.getBindingType());
  }

  @Test
  void getInstanceNullThrows() {
    assertThrows(IllegalArgumentException.class, () -> SignedDocumentBinding.getInstance(null));
  }

  @Test
  void constructorRejectsWrongSequenceSize() {
    final ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new DEROctetString(HASH)); // only one element; dataTbsHash without hashAlg
    final ASN1Sequence tooShort = new DERSequence(v);
    assertThrows(IllegalArgumentException.class, () -> SignedDocumentBinding.getInstance(tooShort));
  }

  @Test
  void encodeRejectsNullDataTbsHash() {
    final SignedDocumentBinding binding = new SignedDocumentBinding(HASH, SHA256, "cose");
    binding.setDataTbsHash(null);
    assertThrows(NullPointerException.class, () -> binding.getEncoded("DER"));
  }

  @Test
  void encodeRejectsNullHashAlg() {
    final SignedDocumentBinding binding = new SignedDocumentBinding(HASH, SHA256, "cose");
    binding.setHashAlg(null);
    assertThrows(NullPointerException.class, () -> binding.getEncoded("DER"));
  }

  @Test
  void bindingTypeCanBeClearedAndOmittedFromEncoding() throws IOException {
    final SignedDocumentBinding binding = new SignedDocumentBinding(HASH, SHA256, "cades");
    binding.setBindingType(null);

    final byte[] encoded = binding.getEncoded("DER");
    // Clearing the optional field must drop it from the encoding (2 elements).
    assertEquals(2, ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encoded)).size());
    assertNull(SignedDocumentBinding.getInstance(encoded).getBindingType());
  }

  @Test
  void toStringRendersJcaDigestName() {
    final SignedDocumentBinding binding = new SignedDocumentBinding(HASH, SHA256, "cades");
    final String s = binding.toString();
    assertTrue(s.contains("SHA-256"), "toString should render the JCA digest name");
    assertFalse(s.contains(NISTObjectIdentifiers.id_sha256.getId()),
        "toString should not render the raw digest OID");
  }

  private static void assertHashAlgIsSha256(final AlgorithmIdentifier alg) {
    assertEquals(NISTObjectIdentifiers.id_sha256, alg.getAlgorithm());
    assertNull(alg.getParameters(),
        "SHA-256 AlgorithmIdentifier must have absent parameters (RFC 5754)");
  }
}
