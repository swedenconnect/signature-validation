/*
 * Copyright (c) 2022. IDsec Solutions AB
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

package se.swedenconnect.sigval.report.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import se.swedenconnect.sigval.commons.data.SigValIdentifiers;

import java.util.Arrays;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
@Getter
public enum SubIndication {

  FORMAT_FAILURE("urn:etsi:019102:subindication:FORMAT_FAILURE"),
  HASH_FAILURE("urn:etsi:019102:subindication:HASH_FAILURE"),
  SIG_CRYPTO_FAILURE("urn:etsi:019102:subindication:SIG_CRYPTO_FAILURE"),
  REVOKED("urn:etsi:019102:subindication:REVOKED"),
  SIG_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:SIG_CONSTRAINTS_FAILURE"),
  CHAIN_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:CHAIN_CONSTRAINTS_FAILURE"),
  CERTIFICATE_CHAIN_GENERAL_FAILURE("urn:etsi:019102:subindication:CERTIFICATE_CHAIN_GENERAL_FAILURE"),
  CRYPTO_CONSTRAINTS_FAILURE("urn:etsi:019102:subindication:CRYPTO_CONSTRAINTS_FAILURE"),
  EXPIRED("urn:etsi:019102:subindication:EXPIRED"),
  NOT_YET_VALID("urn:etsi:019102:subindication:NOT_YET_VALID"),
  POLICY_PROCESSING_ERROR("urn:etsi:019102:subindication:POLICY_PROCESSING_ERROR"),
  SIGNATURE_POLICY_NOT_AVAILABLE("urn:etsi:019102:subindication:SIGNATURE_POLICY_NOT_AVAILABLE"),
  TIMESTAMP_ORDER_FAILURE("urn:etsi:019102:subindication:TIMESTAMP_ORDER_FAILURE"),
  NO_SIGNING_CERTIFICATE_FOUND("urn:etsi:019102:subindication:NO_SIGNING_CERTIFICATE_FOUND"),
  NO_CERTIFICATE_CHAIN_FOUND("urn:etsi:019102:subindication:NO_CERTIFICATE_CHAIN_FOUND"),
  REVOKED_NO_POE("urn:etsi:019102:subindication:REVOKED_NO_POE"),
  REVOKED_CA_NO_POE("urn:etsi:019102:subindication:REVOKED_CA_NO_POE"),
  OUT_OF_BOUNDS_NO_POE("urn:etsi:019102:subindication:OUT_OF_BOUNDS_NO_POE"),
  CRYPTO_CONSTRAINTS_FAILURE_NO_POE("urn:etsi:019102:subindication:CRYPTO_CONSTRAINTS_FAILURE_NO_POE"),
  NO_POE("urn:etsi:019102:subindication:NO_POE"),
  TRY_LATER("urn:etsi:019102:subindication:TRY_LATER"),
  SIGNED_DATA_NOT_FOUND("urn:etsi:019102:subindication:SIGNED_DATA_NOT_FOUND"),
  CUSTOM("urn:etsi:019102:subindication:CUSTOM"),
  REVOCATION_OUT_OF_BOUNDS_NO_POE("urn:etsi:019102:subindication:REVOCATION_OUT_OF_BOUNDS_NO_POE"),
  DOCUMENT_PARTIALLY_SIGNED(SigValIdentifiers.SIG_VALIDATION_SUBINDICATION_PARTIALLY_SIGNED);


  /**
   * The URI of the sub indication
   * @return URI of the sub indication
   */
  private String uri;

  /**
   * Get sub Indication from URI
   * @param uri sub indication URI
   * @return {@link SubIndication}
   * @throws IllegalArgumentException if no such URI exists
   */
  public static SubIndication fromUri(String uri) {
    return Arrays.stream(values())
      .filter(subIndication -> subIndication.getUri().equalsIgnoreCase(uri))
      .findFirst()
      .orElseThrow(() -> new IllegalArgumentException("No such sub indication URI"));
  }

}
