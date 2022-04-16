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

package se.swedenconnect.sigval.report.validationobjects;

import lombok.AllArgsConstructor;
import lombok.Getter;
import se.swedenconnect.sigval.commons.data.SigValIdentifiers;

import java.util.Arrays;

/**
 * Enumerates all ETSI validation report validation object types
 * <p>
 * Current defined object types
 * urn:etsi:019102:validationObject:certificate
 * urn:etsi:019102:validationObject:CRL
 * urn:etsi:019102:validationObject:OCSPResponse
 * urn:etsi:019102:validationObject:timestamp
 * urn:etsi:019102:validationObject:evidencerecord
 * urn:etsi:019102:validationObject:publicKey
 * urn:etsi:019102:validationObject:signedData
 * urn:etsi:019102:validationObject:other
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
@AllArgsConstructor
public enum ValidationObjectType {
  certificate("C", "urn:etsi:019102:validationObject:certificate"),
  CRL("CRL", "urn:etsi:019102:validationObject:CRL"),
  OCSPResponse("O", "urn:etsi:019102:validationObject:OCSPResponse"),
  timestamp("T", "urn:etsi:019102:validationObject:timestamp"),
  evidencerecord("E", "urn:etsi:019102:validationObject:evidencerecord"),
  publicKey("PK", "urn:etsi:019102:validationObject:publicKey"),
  signedData("SD", "urn:etsi:019102:validationObject:signedData"),
  svt("SVT", SigValIdentifiers.TIME_VERIFICATION_TYPE_SVT),
  verifiedTime("VT", SigValIdentifiers.VERIFIED_TIME),
  other("O", "urn:etsi:019102:validationObject:other");

  private String prefix;
  private String uriIdentifier;

  /**
   * Obtains the enumeration representation of a validation object type identifier URI
   * @param uriIdentifier validation object URI identifier
   * @return enumeration object matching the provided identifier or null on no-match
   */
  public static ValidationObjectType getSignatureValidationObjectType(String uriIdentifier) {
    return Arrays.stream(values())
      .filter(validationObjectType -> validationObjectType.getUriIdentifier().equalsIgnoreCase(uriIdentifier))
      .findFirst()
      .orElse(null);
  }
}
