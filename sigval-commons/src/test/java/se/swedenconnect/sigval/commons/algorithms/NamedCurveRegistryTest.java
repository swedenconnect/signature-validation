/*
 * Copyright 2021-2025 Sweden Connect
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
package se.swedenconnect.sigval.commons.algorithms;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link NamedCurveRegistry}.
 */
class NamedCurveRegistryTest {

  @Test
  void get_nistP256_returnsCorrectKeyLength() throws NoSuchAlgorithmException {
    NamedCurve curve = NamedCurveRegistry.get(SECObjectIdentifiers.secp256r1);
    assertEquals(256, curve.getKeyLen());
    assertEquals(SECObjectIdentifiers.secp256r1, curve.getOid());
  }

  @Test
  void get_nistP384_returnsCorrectKeyLength() throws NoSuchAlgorithmException {
    NamedCurve curve = NamedCurveRegistry.get(SECObjectIdentifiers.secp384r1);
    assertEquals(384, curve.getKeyLen());
  }

  @Test
  void get_nistP521_returnsCorrectKeyLength() throws NoSuchAlgorithmException {
    NamedCurve curve = NamedCurveRegistry.get(SECObjectIdentifiers.secp521r1);
    assertEquals(521, curve.getKeyLen());
  }

  @Test
  void get_nistP192_returnsCorrectKeyLength() throws NoSuchAlgorithmException {
    NamedCurve curve = NamedCurveRegistry.get(SECObjectIdentifiers.secp192r1);
    assertEquals(192, curve.getKeyLen());
  }

  @Test
  void get_brainpoolP256r1_returnsCorrectKeyLength() throws NoSuchAlgorithmException {
    NamedCurve curve = NamedCurveRegistry.get(TeleTrusTObjectIdentifiers.brainpoolP256r1);
    assertEquals(256, curve.getKeyLen());
  }

  @Test
  void get_brainpoolP512r1_returnsCorrectKeyLength() throws NoSuchAlgorithmException {
    NamedCurve curve = NamedCurveRegistry.get(TeleTrusTObjectIdentifiers.brainpoolP512r1);
    assertEquals(512, curve.getKeyLen());
  }

  @Test
  void allDefaultCurves_areRegistered() throws NoSuchAlgorithmException {
    for (NamedCurveRegistry.DefaultCurve defaultCurve : NamedCurveRegistry.DefaultCurve.values()) {
      NamedCurve curve = NamedCurveRegistry.get(defaultCurve.getOid());
      assertEquals(defaultCurve.getKeyLen(), curve.getKeyLen(),
          "Key length mismatch for " + defaultCurve.name());
      assertEquals(defaultCurve.getOid(), curve.getOid(),
          "OID mismatch for " + defaultCurve.name());
    }
  }

  @Test
  void get_null_throwsNoSuchAlgorithmException() {
    assertThrows(NoSuchAlgorithmException.class, () -> NamedCurveRegistry.get(null));
  }

  @Test
  void get_unknownOid_throwsNoSuchAlgorithmException() {
    ASN1ObjectIdentifier unknownOid = new ASN1ObjectIdentifier("1.2.3.4.99999");
    assertThrows(NoSuchAlgorithmException.class, () -> NamedCurveRegistry.get(unknownOid));
  }

  @Test
  void registerCurve_existingOid_returnsFalse() {
    boolean result = NamedCurveRegistry.registerCurve(SECObjectIdentifiers.secp256r1, 256);
    assertFalse(result);
  }

  @Test
  void registerCurve_newOid_returnsTrue() throws NoSuchAlgorithmException {
    ASN1ObjectIdentifier newOid = new ASN1ObjectIdentifier("1.2.3.4." + (System.nanoTime() % 100000));
    boolean result = NamedCurveRegistry.registerCurve(newOid, 999);
    assertTrue(result);
    NamedCurve curve = NamedCurveRegistry.get(newOid);
    assertEquals(999, curve.getKeyLen());
  }
}
