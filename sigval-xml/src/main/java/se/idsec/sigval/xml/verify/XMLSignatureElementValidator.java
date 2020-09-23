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

package se.idsec.sigval.xml.verify;

import org.w3c.dom.Element;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.sigval.xml.data.ExtendedXmlSigvalResult;
import se.idsec.sigval.xml.xmlstruct.SignatureData;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContext;

/**
 * Interface for XML signature element validator
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface XMLSignatureElementValidator {

  /**
   * validates the signature represented by a single signature element
   * @param signature signature element
   * @param signatureData {@link SignatureData} signature data extracted for this signature
   * @return {@link ExtendedXmlSigvalResult} signature validation result
   */
  ExtendedXmlSigvalResult validateSignature(final Element signature, final SignatureData signatureData);

  /**
   * Ge the certificate validator. This function is added to support the extended interface of the XML document validator.
   * In this implementation, the certificate validator is specified within the signature element validator using this interface
   * but the XML document validator has a function to get this certificate validator, so it can get it using this function.
   *
   * @return certificate validator
   */
  CertificateValidator getCertificateValidator();
}
