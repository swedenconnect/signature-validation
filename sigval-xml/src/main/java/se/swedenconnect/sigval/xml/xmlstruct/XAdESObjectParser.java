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
package se.swedenconnect.sigval.xml.xmlstruct;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import se.swedenconnect.cert.extensions.AuthnContext;
import se.swedenconnect.schemas.etsi.xades_1_3_2.*;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithmRegistry;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Parser for parsing XAdES object data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XAdESObjectParser implements XMLSigConstants {

  /** XAdES Qualifying properties if present */
  @Getter private QualifyingProperties qualifyingProperties;
  /** Claimed signing time if present */
  @Getter private Date claimedSigningTime;
  /** List of XAdES signed certificate hashes */
  @Getter List<DigestAlgAndValueType> certHashList;
  /** Signature policy identifier if present */
  @Getter SignaturePolicyIdentifier signaturePolicyIdentifier;
  /** List of signature timestamps if present */
  @Getter List<XadesSignatureTimestampData> signatureTimeStampDataList;

  /**
   * Constructor
   * @param sigNode The signature element node to parse for XAdES data
   * @param signatureData signature data collected for this signature
   * @throws XMLSecurityException on general errors
   * @throws JAXBException on XML parsing errors
   */
  public XAdESObjectParser(Element sigNode, SignatureData signatureData) throws XMLSecurityException, JAXBException {

    qualifyingProperties = null;
    NodeList qpNodes = sigNode.getElementsByTagNameNS(XADES_NAMESPACE, "QualifyingProperties");

    for (int i=0 ; i< qpNodes.getLength() ; i++){
      JAXBContext jaxbContext = getXAdESContext();
      QualifyingProperties qp = (QualifyingProperties) jaxbContext.createUnmarshaller().unmarshal(qpNodes.item(i));
      try {
        if (signatureData.getRefDataMap().containsKey("#" + qp.getSignedProperties().getId())) {
          qualifyingProperties = qp;
          break;
        }
      } catch (Exception ex){
        log.debug("Error when parsing Qualifying properties: {}", ex.getMessage());
      }
    }
    if (qualifyingProperties != null){
      parseQualifyingProperties();
    }
  }

  /**
   * Indicates if this is a XAdES signature and the signed signature reference match the signature certificate
   * @param signerCert the signer certificate of this signature
   * @return true if this is a XAdES signature and the signed signature reference match the signature certificate
   */
  public boolean isXadesVerified(X509Certificate signerCert){
    if (certHashList == null || certHashList.isEmpty()){
      return false;
    }
    for (DigestAlgAndValueType digestAlgAndValue : certHashList){
      try {
        String digestAlgorithmUri = digestAlgAndValue.getDigestMethod().getAlgorithm();
        MessageDigest messageDigest = DigestAlgorithmRegistry.get(digestAlgorithmUri).getInstance();
        byte[] signerCertDigest = messageDigest.digest(signerCert.getEncoded());
        if (Arrays.equals(signerCertDigest, digestAlgAndValue.getDigestValue())) return true;
      } catch (Exception ex){
        log.debug("Error parsing XAdES cert ref digest: {}", ex.getMessage());
      }
    }
    return false;
  }

  private void parseQualifyingProperties() {

    // Get signed properties
    try {
      // Attempt to get signing time
      SignedSignatureProperties signedSignatureProperties = qualifyingProperties.getSignedProperties().getSignedSignatureProperties();
      XMLGregorianCalendar xmlSigningTime = signedSignatureProperties.getSigningTime();
      if (xmlSigningTime != null){
        claimedSigningTime = xmlSigningTime.toGregorianCalendar().getTime();
      }
      // Get signed certificate references
      SigningCertificateV2 signingCertificateV2 = signedSignatureProperties.getSigningCertificateV2();
      if (signingCertificateV2 != null){
        certHashList = signingCertificateV2.getCerts().stream()
          .map(certIDTypeV2 -> certIDTypeV2.getCertDigest())
          .collect(Collectors.toList());
      } else {
        SigningCertificate signingCertificate = signedSignatureProperties.getSigningCertificate();
        if (signingCertificate != null){
          certHashList = signingCertificate.getCerts().stream()
            .map(certIDType -> certIDType.getCertDigest())
            .collect(Collectors.toList());
        }
      }
      // Get signature policy
      signaturePolicyIdentifier = signedSignatureProperties.getSignaturePolicyIdentifier();

    } catch (Exception ex){
      log.error("Error parsing XAdES signed properties content: {}", ex.getMessage());
    }

    // Get any present timestamps
    signatureTimeStampDataList = new ArrayList<>();
    try {
      UnsignedSignatureProperties unsignedSignatureProperties = qualifyingProperties.getUnsignedProperties()
        .getUnsignedSignatureProperties();
      List<Object> objectList = unsignedSignatureProperties.getCounterSignaturesAndSignatureTimeStampsAndCompleteCertificateRefs();

      List<XAdESTimeStampType> timeStampTypeList = objectList.stream()
        .filter(o -> JAXBElement.class.isInstance(o))
        .map(JAXBElement.class::cast)
        .filter(jaxbElement -> isSignatureTimestamp(jaxbElement))
        .map(jaxbElement -> (XAdESTimeStampType)jaxbElement.getValue())
        .collect(Collectors.toList());

      for (XAdESTimeStampType xadesTs : timeStampTypeList){
        List<Object> encapsulatedTimeStampsAndXMLTimeStamps = xadesTs.getEncapsulatedTimeStampsAndXMLTimeStamps();
        Optional<EncapsulatedPKIDataType> timeStampOptional = encapsulatedTimeStampsAndXMLTimeStamps.stream()
          .filter(o -> o instanceof EncapsulatedPKIDataType)
          .map(o -> (EncapsulatedPKIDataType) o)
          .findFirst();
        if (timeStampOptional.isPresent()){
          signatureTimeStampDataList.add(XadesSignatureTimestampData.builder()
            .canonicalizationMethod(xadesTs.getCanonicalizationMethod().getAlgorithm())
            .timeStampSignatureBytes(timeStampOptional.get().getValue())
            .build());
        }
      }
    } catch (Exception ex) {
      log.debug("No Timestamp data was available from XAdES data");
    }
  }

  private boolean isSignatureTimestamp(JAXBElement<?> jaxbElement) {
    QName qName = jaxbElement.getName();
    return qName.getNamespaceURI().equals("http://uri.etsi.org/01903/v1.3.2#")
      && qName.getLocalPart().equals("SignatureTimeStamp")
      && jaxbElement.getDeclaredType().equals(XAdESTimeStampType.class);
  }

  @SuppressWarnings("unused")
  private JAXBContext getXAdESContextv1() throws JAXBException {
    return se.swedenconnect.schemas.etsi.xades_1_3_2.JAXBContextFactory.createContext();
  }

  private JAXBContext getXAdESContext() throws JAXBException {
    return JAXBContext.newInstance(
      "se.swedenconnect.schemas.etsi.xades_1_3_2",
      AuthnContext.class.getClassLoader()
    );
  }
}
