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
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.sigval.commons.svt.AbstractSVTSigValClaimsIssuer;
import se.idsec.sigval.svt.claims.*;
import se.idsec.sigval.xml.data.ExtendedXmlSigvalResult;
import se.idsec.sigval.xml.verify.XMLSignatureElementValidator;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class XMLSVTSigValClaimsIssuer extends AbstractSVTSigValClaimsIssuer<XMLSigValInput> {
  //TODO  This is the next big task in order to issue SVT for XML docs

  /**  */
  private final XMLSignatureElementValidator signatureVerifier;

  /** If this is true and signature validation did not provide any policy validation conclusion, then set basic validation level */
  @Setter private boolean defaultBasicValidation = false;

  /**
   * @param algorithm    the algorithm used to sign the SVT as well as selecting the Hash algorithm used to generate SVT hash values
   * @param privateKey   private key used to sign the SVT
   * @param certificates certificates supporting the SVT signature
   * @throws NoSuchAlgorithmException
   * @throws JOSEException
   */
  public XMLSVTSigValClaimsIssuer(JWSAlgorithm algorithm, Object privateKey,
    List<X509Certificate> certificates, XMLSignatureElementValidator signatureVerifier) throws NoSuchAlgorithmException, JOSEException {
    super(algorithm, privateKey, certificates);
    this.signatureVerifier = signatureVerifier;
  }

  /** {@inheritDoc} */
  @Override protected List<SignatureClaims> verify(XMLSigValInput sigValInput, String hashAlgoUri) throws Exception {

    ExtendedXmlSigvalResult sigResult = signatureVerifier.validateSignature(sigValInput.getSignatureElement(),
      sigValInput.getSignatureContext());

    SignatureClaims claimsData = SignatureClaims.builder()
      .sig_ref(getSigRefData(sigResult, hashAlgoUri))
      .sig_val(getSignaturePolicyValidations(sigResult))
      .sig_data_ref(getDocRefHashes(sigResult, hashAlgoUri))
      .time_val(
        sigResult.getTimeValidationResults().stream()
          .map(pdfTimeValidationResult -> pdfTimeValidationResult.getTimeValidationClaims())
          .filter(timeValidationClaims -> isVerifiedTime(timeValidationClaims))
          .collect(Collectors.toList())
      )
      .signer_cert_ref(getCertRef(sigResult, hashAlgoUri))
      .build();

    return Arrays.asList(claimsData);
  }


  private List<SignedDataClaims> getDocRefHashes(ExtendedXmlSigvalResult sigResult, String hashAlgoUri) {
    return new ArrayList<>();
  }

  private SigReferenceClaims getSigRefData(ExtendedXmlSigvalResult sigResult, String hashAlgoUri) {
    return null;
  }

  /** {@inheritDoc} */
  @Override protected SVTProfile getSvtProfile() {
    return SVTProfile.XML;
  }
}
