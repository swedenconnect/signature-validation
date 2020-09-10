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

package se.idsec.sigval.xml.svt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import se.idsec.sigval.svt.claims.SVTProfile;
import se.idsec.sigval.svt.claims.SignatureClaims;
import se.idsec.sigval.svt.issuer.SVTIssuer;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;

public class XMLSVTSigValClaimsIssuer extends SVTIssuer {

  /**
   * @param algorithm    the algorithm used to sign the SVT as well as selecting the Hash algorithm used to generate SVT hash values
   * @param privateKey   private key used to sign the SVT
   * @param certificates certificates supporting the SVT signature
   * @throws NoSuchAlgorithmException
   * @throws JOSEException
   */
  public XMLSVTSigValClaimsIssuer(JWSAlgorithm algorithm, Object privateKey,
    List<X509Certificate> certificates) throws NoSuchAlgorithmException, JOSEException {
    super(algorithm, privateKey, certificates);
  }

  /** {@inheritDoc} */
  @Override protected List<SignatureClaims> verify(byte[] signedDocument, String hashAlgoUri) throws Exception {
    return null;
  }

  /** {@inheritDoc} */
  @Override protected SVTProfile getSvtProfile() {
    return SVTProfile.XML;
  }
}
