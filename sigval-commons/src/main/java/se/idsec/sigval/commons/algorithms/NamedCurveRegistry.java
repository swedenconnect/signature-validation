/*
 * Copyright (c) 2020. IDsec Solutions AB
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

package se.idsec.sigval.commons.algorithms;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Registry over supported named EC curves.
 *
 * Any EC curve can be specified using the defined curve parameters of EC cryptography.
 * Some curves with specific parameters have been assigned OID identifiers. These are called "named curves"
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NamedCurveRegistry {

  private static Map<ASN1ObjectIdentifier, NamedCurve> namedCurveMap;

  static {
    namedCurveMap = new HashMap<>();
    registerCurve(DefaultCurve.NIST_P_192);
    registerCurve(DefaultCurve.NIST_P_224);
    registerCurve(DefaultCurve.NIST_P_256);
    registerCurve(DefaultCurve.NIST_P_384);
    registerCurve(DefaultCurve.NIST_P_521);
    registerCurve(DefaultCurve.brainpoolP160r1);
    registerCurve(DefaultCurve.brainpoolP192r1);
    registerCurve(DefaultCurve.brainpoolP224r1);
    registerCurve(DefaultCurve.brainpoolP256r1);
    registerCurve(DefaultCurve.brainpoolP320r1);
    registerCurve(DefaultCurve.brainpoolP384r1);
    registerCurve(DefaultCurve.brainpoolP512r1);
  }

  /**
   * Internal function to register default curves
   * @param curve the curve to register
   */
  private static void registerCurve(DefaultCurve curve){
    registerCurve(curve.getOid(), curve.getKeyLen());
  }

  /**
   * Register new named curve
   * @param oid Object Identifier
   * @param keyLen key length
   * @return true if the named cuve was added to the registry
   */
  public static boolean registerCurve(ASN1ObjectIdentifier oid, int keyLen){
    if (namedCurveMap.containsKey(oid)){
      return false;
    }
    namedCurveMap.put(oid, new NamedCurve(oid, keyLen));
    return true;
  }

  /**
   * Get supported named curve based on Object Identifier
   * @param oid Object Identifier
   * @return named curve
   * @throws NoSuchAlgorithmException if the requested curve was not in the registry
   */
  public static NamedCurve get(ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException {
    if (oid == null){
      throw new NoSuchAlgorithmException("Null curve oid");
    }
    Optional<NamedCurve> namedCurveOptional = namedCurveMap.keySet().stream()
      .map(asn1ObjectIdentifier -> namedCurveMap.get(asn1ObjectIdentifier))
      .filter(namedCurve -> namedCurve.getOid().equals(oid))
      .findFirst();

    if (namedCurveOptional.isPresent()){
      return namedCurveOptional.get();
    }

    throw new NoSuchAlgorithmException("EC Curve with oid " + oid.getId() + " is not registered");
  }

  /**
   * Default named curve for the registry
   */
  @AllArgsConstructor
  @Getter
  public enum DefaultCurve {
    NIST_P_192(SECObjectIdentifiers.secp192r1, 192),
    NIST_P_224(SECObjectIdentifiers.secp224r1, 224),
    NIST_P_256(SECObjectIdentifiers.secp256r1, 256),
    NIST_P_384(SECObjectIdentifiers.secp384r1, 384),
    NIST_P_521(SECObjectIdentifiers.secp521r1, 521),
    brainpoolP160r1(TeleTrusTObjectIdentifiers.brainpoolP160r1, 160),
    brainpoolP192r1(TeleTrusTObjectIdentifiers.brainpoolP192r1, 192),
    brainpoolP224r1(TeleTrusTObjectIdentifiers.brainpoolP224r1, 224),
    brainpoolP256r1(TeleTrusTObjectIdentifiers.brainpoolP256r1, 256),
    brainpoolP320r1(TeleTrusTObjectIdentifiers.brainpoolP320r1, 320),
    brainpoolP384r1(TeleTrusTObjectIdentifiers.brainpoolP384r1, 384),
    brainpoolP512r1(TeleTrusTObjectIdentifiers.brainpoolP512r1, 512);

    private ASN1ObjectIdentifier oid;
    private int keyLen;
  }

}
