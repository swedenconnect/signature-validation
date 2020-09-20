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

import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import se.idsec.sigval.svt.issuer.SVTModel;
import se.idsec.sigval.xml.utils.XMLSigUtils;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContext;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContextFactory;
import se.idsec.sigval.xml.xmlstruct.impl.DefaultXMLSignatureContextFactory;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class XMLDocumentSVTIssuer {

  private final XMLSVTSigValClaimsIssuer svtClaimsIssuer;
  @Setter private XMLSignatureContextFactory signatureContextFactory;

  public XMLDocumentSVTIssuer(XMLSVTSigValClaimsIssuer svtClaimsIssuer) {
    this.svtClaimsIssuer = svtClaimsIssuer;
    this.signatureContextFactory = new DefaultXMLSignatureContextFactory();
  }

  public byte[] issueSvt(Document document, SVTModel svtModel, XMLDocumentSVTMethod svtMethod) throws Exception {

    List<Element> signatures = XMLSigUtils.getSignatures(document);

    XMLSignatureContext signatureContext = signatureContextFactory.getSignatureContext(document);

    // Verify all signatures ...
    //
    List<SVTExtensionData> svtExtensionDataList = new ArrayList<>();
    for (Element signature : signatures) {
      SignedJWT signedSvtJWT = null;
      try {
        signedSvtJWT = svtClaimsIssuer.getSignedSvtJWT(
          XMLSigValInput.builder()
            .signatureContext(signatureContext)
            .signatureElement(signature)
            .svtMethod(svtMethod)
            .build(), svtModel
        );
        if (signedSvtJWT != null)
          svtExtensionDataList.add(new SVTExtensionData(signature, signedSvtJWT));
      }
      catch (Exception ex) {
        log.error("Signature validation claims collection caused error: {}", ex.getMessage(), ex);
      }
    }
    return extendDocumentSignature(document, svtExtensionDataList, signatureContext);
  }

  private byte[] extendDocumentSignature(Document document, List<SVTExtensionData> svtExtensionDataList,
    XMLSignatureContext signatureContext) {
    //TODO extend the signature with SVT
    return new byte[] {};
  }

  @Data
  @AllArgsConstructor
  private class SVTExtensionData {

    private Element element;
    private SignedJWT signedJWT;

  }

}
