/*
 * Copyright (c) 2024.  Sweden Connect
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

package se.swedenconnect.sigval.commons.svt;

import java.text.ParseException;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.sigval.svt.claims.SVTClaims;
import se.swedenconnect.sigval.svt.claims.ValidationConclusion;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/**
 * Utility functions for SVT processing in signature validation context
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class SVTUtils {

  private static final JsonMapper JSON_MAPPER = new JsonMapper();

  public static boolean checkValidatedSignatures(SignedJWT signedSvtJWT) throws ParseException, JacksonException {
    if (signedSvtJWT == null) {
      return false;
    }
    JWTClaimsSet claimsSet = signedSvtJWT.getJWTClaimsSet();
    SVTClaims svtClaims = JSON_MAPPER.readValue(
      JSON_MAPPER.writeValueAsString(claimsSet.getClaim("sig_val_claims")),
      SVTClaims.class);
    boolean allValidSignatures = svtClaims.getSig().stream()
      .allMatch(signatureClaims -> signatureClaims.getSig_val()
        .stream()
        .allMatch(policyValidationClaims -> policyValidationClaims.getRes().equals(
          ValidationConclusion.PASSED)));
    return allValidSignatures;
  }


  public static boolean checkIfSVTShouldBeIssued(SignedJWT signedSvtJWT, boolean issueSvtOnFailedValidation)
    throws ParseException, JacksonException {
    if (signedSvtJWT == null) {
      log.debug("Null SVT issued");
      return false;
    }
    boolean allValidSignatures = checkValidatedSignatures(signedSvtJWT);
    if (allValidSignatures) {
      log.debug("All signatures are valid. Issue SVT");
      return true;
    }
    if (issueSvtOnFailedValidation) {
      log.debug("Not all signatures are valid, but policy admit SVT issuance even if not all signatures are valid. Issue SVT");
      return true;
    }
    log.debug("Not all signatures are valid. Fail SVT issuance by policy");
    return false;
  }
}
