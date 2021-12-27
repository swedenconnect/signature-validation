/*
 * Copyright (c) 2020. Sweden Connect
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

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Registry of supported digest algorithms
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class DigestAlgorithmRegistry {

  private static Map<String, DigestAlgorithm> digestAlgorithmMap;

  static{
    digestAlgorithmMap = new HashMap<>();
    registerDigestAlgorithm(DigestAlgorithm.ID_SHA1, DigestAlgorithm.OID_SHA1);
    registerDigestAlgorithm(DigestAlgorithm.ID_SHA224, DigestAlgorithm.OID_SHA224);
    registerDigestAlgorithm(DigestAlgorithm.ID_SHA256, DigestAlgorithm.OID_SHA256);
    registerDigestAlgorithm(DigestAlgorithm.ID_SHA384, DigestAlgorithm.OID_SHA384);
    registerDigestAlgorithm(DigestAlgorithm.ID_SHA512, DigestAlgorithm.OID_SHA512);
    registerDigestAlgorithm(DigestAlgorithm.ID_SHA3_224, DigestAlgorithm.OID_SHA3_224);
    registerDigestAlgorithm(DigestAlgorithm.ID_SHA3_256, DigestAlgorithm.OID_SHA3_256);
    registerDigestAlgorithm(DigestAlgorithm.ID_SHA3_384, DigestAlgorithm.OID_SHA3_384);
    registerDigestAlgorithm(DigestAlgorithm.ID_SHA3_512, DigestAlgorithm.OID_SHA3_512);
  }

  /**
   * Register a new supported digest algorithm
   * @param uri URI identifier
   * @param oid Object Identifier (OID)
   * @return true if the digest algorithm was added to the registry
   */
  public static boolean registerDigestAlgorithm(String uri, ASN1ObjectIdentifier oid){
    if (digestAlgorithmMap.containsKey(uri)){
      return false;
    }
    digestAlgorithmMap.put(uri, new DigestAlgorithm(uri, oid));
    return true;
  }

  /**
   * Get registered digest algorithm based on URI identifier
   * @param uri URI identifier
   * @return digest algorithm
   * @throws NoSuchAlgorithmException if the requested digest algorithm is not in the registry
   */
  public static DigestAlgorithm get(String uri) throws NoSuchAlgorithmException {
    if (uri == null){
      throw new NoSuchAlgorithmException("Null digest algorithm");
    }
    if (digestAlgorithmMap.containsKey(uri)){
      return digestAlgorithmMap.get(uri);
    }
    throw new NoSuchAlgorithmException("Digest algorithm "+ uri + " is not registered");
  }

  /**
   * Get registered digest algorithm based on OID
   * @param oid Object Identifier (OID)
   * @return digest algorithm
   * @throws NoSuchAlgorithmException if the requested digest algorithm is not in the registry
   */
  public static DigestAlgorithm get(ASN1ObjectIdentifier oid) throws NoSuchAlgorithmException {
    if (oid == null){
      throw new NoSuchAlgorithmException("Null digest algorithm");
    }
    Optional<DigestAlgorithm> digestAlgorithmOptional = digestAlgorithmMap.keySet().stream()
      .map(s -> digestAlgorithmMap.get(s))
      .filter(digestAlgorithm -> digestAlgorithm.getOid().equals(oid))
      .findFirst();

    if (digestAlgorithmOptional.isPresent()){
      return digestAlgorithmOptional.get();
    }
    throw new NoSuchAlgorithmException("Digest algorithm "+ oid.getId() + " is not registered");
  }
}
