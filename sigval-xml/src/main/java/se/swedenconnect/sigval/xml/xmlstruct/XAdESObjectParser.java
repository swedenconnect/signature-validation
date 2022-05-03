/*
 * Copyright (c) 2020-2022. Sweden Connect
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

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.xml.JAXBContextUtils;
import se.swedenconnect.schemas.etsi.xades_1_3_2.DigestAlgAndValueType;
import se.swedenconnect.schemas.etsi.xades_1_3_2.EncapsulatedPKIDataType;
import se.swedenconnect.schemas.etsi.xades_1_3_2.QualifyingProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SignaturePolicyIdentifier;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SignedSignatureProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SigningCertificate;
import se.swedenconnect.schemas.etsi.xades_1_3_2.SigningCertificateV2;
import se.swedenconnect.schemas.etsi.xades_1_3_2.UnsignedSignatureProperties;
import se.swedenconnect.schemas.etsi.xades_1_3_2.XAdESTimeStampType;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithmRegistry;

/**
 * Parser for parsing XAdES object data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XAdESObjectParser implements XMLSigConstants {

  /**
   * XAdES Qualifying properties.
   *
   * @return the XAdES Qualifying properties or null
   */
  @Getter
  private QualifyingProperties qualifyingProperties;

  /**
   * Claimed signing time.
   *
   * @return the claimed signing time or null
   */
  @Getter
  private Date claimedSigningTime;

  /**
   * List of XAdES signed certificate hashes.
   *
   * @return a list of XAdES signed certificate hashes
   */
  @Getter
  List<DigestAlgAndValueType> certHashList;

  /**
   * Signature policy identifier.
   *
   * @return the signature policy identifier or null
   */
  @Getter
  SignaturePolicyIdentifier signaturePolicyIdentifier;

  /**
   * List of signature timestamps.
   *
   * @return the ist of signature timestamps or null
   */
  @Getter
  List<XadesSignatureTimestampData> signatureTimeStampDataList;

  /**
   * Constructor
   *
   * @param sigNode
   *          The signature element node to parse for XAdES data
   * @param signatureData
   *          signature data collected for this signature
   * @throws XMLSecurityException
   *           on general errors
   * @throws JAXBException
   *           on XML parsing errors
   */
  public XAdESObjectParser(final Element sigNode, final SignatureData signatureData) throws XMLSecurityException, JAXBException {

    this.qualifyingProperties = null;
    final NodeList qpNodes = sigNode.getElementsByTagNameNS(XMLSigConstants.XADES_NAMESPACE, "QualifyingProperties");

    for (int i = 0; i < qpNodes.getLength(); i++) {
      final JAXBContext jaxbContext = JAXBContextUtils.createJAXBContext(QualifyingProperties.class);
      final QualifyingProperties qp = (QualifyingProperties) jaxbContext.createUnmarshaller().unmarshal(qpNodes.item(i));
      try {
        if (signatureData.getRefDataMap().containsKey("#" + qp.getSignedProperties().getId())) {
          this.qualifyingProperties = qp;
          break;
        }
      }
      catch (final Exception e) {
        log.debug("Error when parsing Qualifying properties: {}", e.getMessage());
      }
    }
    if (this.qualifyingProperties != null) {
      this.parseQualifyingProperties();
    }
  }

  /**
   * Indicates if this is a XAdES signature and the signed signature reference match the signature certificate
   *
   * @param signerCert
   *          the signer certificate of this signature
   * @return true if this is a XAdES signature and the signed signature reference match the signature certificate
   */
  public boolean isXadesVerified(final X509Certificate signerCert) {
    if (this.certHashList == null || this.certHashList.isEmpty()) {
      return false;
    }
    for (final DigestAlgAndValueType digestAlgAndValue : this.certHashList) {
      try {
        final String digestAlgorithmUri = digestAlgAndValue.getDigestMethod().getAlgorithm();
        final MessageDigest messageDigest = DigestAlgorithmRegistry.get(digestAlgorithmUri).getInstance();
        final byte[] signerCertDigest = messageDigest.digest(signerCert.getEncoded());
        if (Arrays.equals(signerCertDigest, digestAlgAndValue.getDigestValue())) {
          return true;
        }
      }
      catch (final Exception e) {
        log.debug("Error parsing XAdES cert ref digest: {}", e.getMessage());
      }
    }
    return false;
  }

  private void parseQualifyingProperties() {

    // Get signed properties
    try {
      // Attempt to get signing time
      final SignedSignatureProperties signedSignatureProperties = this.qualifyingProperties.getSignedProperties()
        .getSignedSignatureProperties();
      final XMLGregorianCalendar xmlSigningTime = signedSignatureProperties.getSigningTime();
      if (xmlSigningTime != null) {
        this.claimedSigningTime = xmlSigningTime.toGregorianCalendar().getTime();
      }
      // Get signed certificate references
      final SigningCertificateV2 signingCertificateV2 = signedSignatureProperties.getSigningCertificateV2();
      if (signingCertificateV2 != null) {
        this.certHashList = signingCertificateV2.getCerts()
          .stream()
          .map(certIDTypeV2 -> certIDTypeV2.getCertDigest())
          .collect(Collectors.toList());
      }
      else {
        final SigningCertificate signingCertificate = signedSignatureProperties.getSigningCertificate();
        if (signingCertificate != null) {
          this.certHashList = signingCertificate.getCerts()
            .stream()
            .map(certIDType -> certIDType.getCertDigest())
            .collect(Collectors.toList());
        }
      }
      // Get signature policy
      this.signaturePolicyIdentifier = signedSignatureProperties.getSignaturePolicyIdentifier();

    }
    catch (final Exception e) {
      log.error("Error parsing XAdES signed properties content: {}", e.getMessage());
    }

    // Get any present timestamps
    this.signatureTimeStampDataList = new ArrayList<>();
    try {
      final UnsignedSignatureProperties unsignedSignatureProperties = this.qualifyingProperties.getUnsignedProperties()
        .getUnsignedSignatureProperties();
      final List<Object> objectList = unsignedSignatureProperties.getCounterSignaturesAndSignatureTimeStampsAndCompleteCertificateRefs();

      final List<XAdESTimeStampType> timeStampTypeList = objectList.stream()
        .filter(o -> JAXBElement.class.isInstance(o))
        .map(JAXBElement.class::cast)
        .filter(jaxbElement -> this.isSignatureTimestamp(jaxbElement))
        .map(jaxbElement -> (XAdESTimeStampType) jaxbElement.getValue())
        .collect(Collectors.toList());

      for (final XAdESTimeStampType xadesTs : timeStampTypeList) {
        final List<Object> encapsulatedTimeStampsAndXMLTimeStamps = xadesTs.getEncapsulatedTimeStampsAndXMLTimeStamps();
        final Optional<EncapsulatedPKIDataType> timeStampOptional = encapsulatedTimeStampsAndXMLTimeStamps.stream()
          .filter(o -> o instanceof EncapsulatedPKIDataType)
          .map(o -> (EncapsulatedPKIDataType) o)
          .findFirst();
        if (timeStampOptional.isPresent()) {
          this.signatureTimeStampDataList.add(XadesSignatureTimestampData.builder()
            .canonicalizationMethod(xadesTs.getCanonicalizationMethod().getAlgorithm())
            .timeStampSignatureBytes(timeStampOptional.get().getValue())
            .build());
        }
      }
    }
    catch (final Exception e) {
      log.debug("No Timestamp data was available from XAdES data");
    }
  }

  private boolean isSignatureTimestamp(final JAXBElement<?> jaxbElement) {
    final QName qName = jaxbElement.getName();
    return qName.getNamespaceURI().equals("http://uri.etsi.org/01903/v1.3.2#")
        && qName.getLocalPart().equals("SignatureTimeStamp")
        && jaxbElement.getDeclaredType().equals(XAdESTimeStampType.class);
  }

  @SuppressWarnings("unused")
  private JAXBContext getXAdESContextv1() throws JAXBException {
    return se.swedenconnect.schemas.etsi.xades_1_3_2.JAXBContextFactory.createContext();
  }

  @SuppressWarnings("unused")
  private JAXBContext getXAdESContext() throws JAXBException {
    return JAXBContext.newInstance(
      "se.swedenconnect.schemas.etsi.xades_1_3_2",
      XAdESObjectParser.class.getClassLoader());
  }
}
