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

package se.swedenconnect.sigval.commons.algorithms;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.apache.xml.security.signature.XMLSignature;

import com.nimbusds.jose.JWSAlgorithm;

/**
 * Registry for JWS signing algorithms
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class JWSAlgorithmRegistry {

  private static Map<String, JWSAlgorithm> jwsAlgorithmMap;

  static {
    jwsAlgorithmMap = new HashMap<>();
    register(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, JWSAlgorithm.RS256);
    register(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384, JWSAlgorithm.RS384);
    register(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512, JWSAlgorithm.RS512);
    register(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, JWSAlgorithm.ES256);
    register(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384, JWSAlgorithm.ES384);
    register(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512, JWSAlgorithm.ES512);
  }

  /**
   * Register a new JWS signing algorithm
   * @param uri URI identifier for the signing algorithm
   * @param algorithm the new JWS algorithm
   * @return true if the algorithm was added to the registry
   */
  public static boolean register(String uri, JWSAlgorithm algorithm){
    if (jwsAlgorithmMap.containsKey(uri)){
      return false;
    }
    jwsAlgorithmMap.put(uri, algorithm);
    return true;
  }

  /**
   * Get the URI identifier of the JWS algorithm
   * @param jwsAlgorithm  JWS algorithm
   * @return URI identifier
   * @throws NoSuchAlgorithmException if the specified algorithm is not in the registry
   */
  public static String getUri(JWSAlgorithm jwsAlgorithm) throws NoSuchAlgorithmException {
    if (jwsAlgorithm == null){
      throw new NoSuchAlgorithmException("Null algorithm");
    }

    for (String  key : jwsAlgorithmMap.keySet()){
      JWSAlgorithm jwsalgo = jwsAlgorithmMap.get(key);
      if (jwsalgo.equals(jwsAlgorithm)){
        return key;
      }
    }
    throw new NoSuchAlgorithmException("Not found JWS Algorithm: " + jwsAlgorithm);
  }

  /**
   * Get the JWS algorithm for a signature algorithm URI identifier
   * @param uri URI identifier
   * @return JWS algorithm
   * @throws NoSuchAlgorithmException if the specified algorithm is not in the registry
   */
  public static JWSAlgorithm get(String uri) throws NoSuchAlgorithmException {
    if (uri == null) {
      throw new NoSuchAlgorithmException("Null algorithm");
    }
    if (jwsAlgorithmMap.containsKey(uri)){
      return jwsAlgorithmMap.get(uri);
    }
    throw new NoSuchAlgorithmException("Not found JWS Algorithm for " + uri);
  }

}
