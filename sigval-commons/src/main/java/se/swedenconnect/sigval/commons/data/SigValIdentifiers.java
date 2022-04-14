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

package se.swedenconnect.sigval.commons.data;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 * Registered identifiers used for signature validation
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SigValIdentifiers {

  /** Signature timestamp */
  public static final String TIME_VERIFICATION_TYPE_SIG_TIMESTAMP = "http://id.swedenconnect.se/svt/timeval-type/sig-timestamp/01";
  /** Document timestamp */
  public static final String TIME_VERIFICATION_TYPE_PDF_DOC_TIMESTAMP = "http://id.swedenconnect.se/svt/timeval-type/pdf-doc-timestamp/01";
  /** Verified time without explicit reference to the source time evidence data */
  public static final String VERIFIED_TIME = "http://id.swedenconnect.se/svt/timeval-type/verified-time/01";
  /** SVT timestamp */
  public static final String TIME_VERIFICATION_TYPE_SVT = "http://id.swedenconnect.se/svt/timeval-type/svt/01";
  /** Basic signature validation against list of trusted certificates. No revocation checking */
  public static final String SIG_VALIDATION_POLICY_BASIC_VALIDATION = "http://id.swedenconnect.se/svt/sigval-policy/basic/01";
  /** Full PKIX path validation to a trust anchor including revocation checking of all intermediary and end certificates */
  public static final String SIG_VALIDATION_POLICY_PKIX_VALIDATION = "http://id.swedenconnect.se/svt/sigval-policy/pkix/01";
  /** Full PKIX path validation allowing revoked certificates revoked after time stamped signing time */
  public static final String SIG_VALIDATION_POLICY_TIMESTAMPED_PKIX_VALIDATION = "http://id.swedenconnect.se/svt/sigval-policy/ts-pkix/01";
  /** Sig status data type identifier for a status message in the signature validation report */
  public static final String SIG_VALIDATION_REPORT_STATUS_MESSAGE = "http://id.swedenconnect.se/svt/sig-val-report/message";
  /** Sig validation status sub indication if the signed document is only partly signed (Signature does not cover whole document */
  public static final String SIG_VALIDATION_SUBINDICATION_PARTIALLY_SIGNED = "http://id.swedenconnect.se/svt/subindication/partially-signed";

  /** Signature method indication for validation of signature based on SVT validation where original validation was pkix validation */
  public static final String SIG_VALIDATION_POLICY_SVT_PKIX_VALIDATION = "http://id.swedenconnect.se/svt/sigval-policy/pkix/01/svt";
  /** Signature method indication for validation of signature based on SVT validation where original validation was pkix validation */
  public static final String SIG_VALIDATION_POLICY_SVT_IMESTAMPED_PKIX_VALIDATION = "http://id.swedenconnect.se/svt/sigval-policy/ts-pkix/01/svt";

  /** Object identifier for the ECDSA algorithm. */
  public static final String ID_ECDSA = "1.2.840.10045.2.1";
  /** Object identifier for the RSA algorithm. */
  public static final String ID_RSA = "1.2.840.113549.1.1.1";

  /** Object identifier for the Sweden Connect timestamp policy */
  public static final ASN1ObjectIdentifier ID_SVT_TS_POLICY = new ASN1ObjectIdentifier("1.2.752.201.2.1");


}
