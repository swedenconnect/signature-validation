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

package se.swedenconnect.sigval.commons.timestamp;

import org.bouncycastle.asn1.tsp.TSTInfo;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for a timestamp policy verifier
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface TimeStampPolicyVerifier {

  /**
   * Verify a timestamp according to a defined policy
   * @param docBytes the bytes of the PDF signature holding the timestamp
   * @param tstInfo TSTInfo of the timestamp
   * @param sigCert the certificate used to sign the time stamp
   * @param certList a list of certificate supporting validation of the signing certificate
   * @return {@link TimeStampPolicyVerificationResult} verification result
   */
  TimeStampPolicyVerificationResult verifyTsPolicy(byte[] docBytes, TSTInfo tstInfo, X509Certificate sigCert, List<X509Certificate> certList);
}
