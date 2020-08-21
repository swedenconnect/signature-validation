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

import com.nimbusds.jose.JWSAlgorithm;
import org.apache.xml.security.signature.XMLSignature;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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

  public static boolean register(String uri, JWSAlgorithm algorithm){
    if (jwsAlgorithmMap.containsKey(uri)){
      return false;
    }
    jwsAlgorithmMap.put(uri, algorithm);
    return true;
  }

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
