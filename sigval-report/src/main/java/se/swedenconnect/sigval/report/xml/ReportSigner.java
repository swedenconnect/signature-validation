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

package se.swedenconnect.sigval.report.xml;

import org.apache.xmlbeans.XmlException;
import org.apache.xmlbeans.XmlObject;
import org.etsi.uri.x19102.v12.ValidationReportDocument;
import org.w3c.dom.Document;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.xml.XMLSigner;
import se.idsec.signservice.security.sign.xml.XMLSignerResult;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSignatureValidator;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSigner;
import se.idsec.signservice.xml.DOMUtils;
import se.swedenconnect.security.credential.BasicCredential;
import se.swedenconnect.security.credential.PkiCredential;

import javax.xml.crypto.dsig.XMLObject;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Signer for signing the signature validation report
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ReportSigner {

  XMLSigner xmlSigner;
  List<X509Certificate> signerChain;

  public ReportSigner(PrivateKey privateKey, List<X509Certificate> signerChain) {
    this.signerChain = signerChain;
    PkiCredential pkiCredential = new BasicCredential(signerChain, privateKey);
    this.xmlSigner = new DefaultXMLSigner(pkiCredential);
  }

  public byte[] signSigvalReport(byte[] report) throws SignatureException, XmlException, IOException {

    Document reportDocument = DOMUtils.bytesToDocument(report);
    XMLSignerResult xmlSignerResult = xmlSigner.sign(reportDocument, null);
    Document signedDocument = xmlSignerResult.getSignedDocument();
    byte[] signedDocuBytes = DOMUtils.nodeToBytes(signedDocument);
    return signedDocuBytes;
  }


}
