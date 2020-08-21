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

package se.idsec.sigval.commons.data;

/**
 * Registered identifiers used for signature validation
 */
public class SigValIdentifiers {

  /** PDF signature timestamp */
  public static final String TIME_VERIFICATION_TYPE_PDF_SIG_TIMESTAMP = "http://id.swedenconnect.se/svt/timeval-type/pdf-sig-timestamp/01";
  /** PDF document timestamp */
  public static final String TIME_VERIFICATION_TYPE_PDF_DOC_TIMESTAMP = "http://id.swedenconnect.se/svt/timeval-type/pdf-doc-timestamp/01";
  /** SVT timestamp */
  public static final String TIME_VERIFICATION_TYPE_SVT = "http://id.swedenconnect.se/svt/timeval-type/svt/01";
  /** Basic signature validation against list of trusted certificates. No revocation checking */
  public static final String SIG_VALIDATION_POLICY_BASIC_VALIDATION = "http://id.swedenconnect.se/svt/sigval-policy/basic/01";
  /** Full PKIX path validation to a trust anchor including revocation checking of all intermediary and end certificates */
  public static final String SIG_VALIDATION_POLICY_PKIX_VALIDATION = "http://id.swedenconnect.se/svt/sigval-policy/pkix/01";

  /** Object identifier for the ECDSA algorithm. */
  public static final String ID_ECDSA = "1.2.840.10045.2.1";
  /** Object identifier for the RSA algorithm. */
  public static final String ID_RSA = "1.2.840.113549.1.1.1";


}
