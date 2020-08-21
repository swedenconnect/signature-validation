package se.idsec.sigval.pdf.utils;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedStream;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.util.CollectionStore;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgorithmRegistry;
import se.idsec.sigval.commons.algorithms.NamedCurve;
import se.idsec.sigval.commons.algorithms.NamedCurveRegistry;
import se.idsec.sigval.commons.algorithms.PublicKeyType;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.timestamp.PDFTimeStamp;
import se.idsec.sigval.svt.claims.TimeValidationClaims;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.logging.Logger;

@Slf4j
public class CMSVerifyUtils {

  /**
   * Extracts signing certificate and supporting certificate chain
   *
   * @throws Exception is certificate extraction fails
   */
  public static PDFSigCerts extractCertificates(CMSSignedDataParser cmsSignedDataParser) throws Exception {
    CollectionStore certStore = (CollectionStore) cmsSignedDataParser.getCertificates();
    Iterator ci = certStore.iterator();
    List<X509Certificate> certList = new ArrayList<>();
    while (ci.hasNext()) {
      certList.add(getCert((X509CertificateHolder) ci.next()));
    }
    SignerInformation signerInformation = cmsSignedDataParser.getSignerInfos().iterator().next();
    Collection certCollection = certStore.getMatches(signerInformation.getSID());
    X509Certificate sigCert = getCert((X509CertificateHolder) certCollection.iterator().next());
    return new PDFSigCerts(sigCert, certList);
  }

  /**
   * Obtains a {@link CMSSignedDataParser}*
   *
   * @param sig          The {@link PDSignature} of the signature
   * @param signedPdfDoc the bytes of the complete PDF document holding this signature
   * @return CMSSignedDataParser
   * @throws CMSException on error
   * @throws IOException  on error
   */
  public static CMSSignedDataParser getCMSSignedDataParser(PDSignature sig, byte[] signedPdfDoc) throws CMSException, IOException {
    return getCMSSignedDataParser(sig.getContents(signedPdfDoc), sig.getSignedContent(signedPdfDoc));
  }

  /**
   * Obtains a {@link CMSSignedDataParser}
   *
   * @param cmsContentInfo The byes of the contents parameter in the signature dictionary containing the bytes of a CMS ContentInfo
   * @param signedDocBytes The bytes of the PDF document signed by this signature. These are the bytes identified by the byteRange parameter
   *                       in the signature dictionary.
   * @return CMSSignedDataParser
   * @throws CMSException on error
   */
  public static CMSSignedDataParser getCMSSignedDataParser(byte[] cmsContentInfo, byte[] signedDocBytes) throws CMSException {
    ByteArrayInputStream bis = new ByteArrayInputStream(signedDocBytes);
    return new CMSSignedDataParser(new BcDigestCalculatorProvider(), new CMSTypedStream(bis), cmsContentInfo);
  }

  public static void getCMSAlgoritmProtectionData(Attribute cmsAlgoProtAttr, ExtendedPdfSigValResult sigResult) {
    if (cmsAlgoProtAttr == null) {
      sigResult.setCmsAlgorithmProtection(false);
      return;
    }
    sigResult.setCmsAlgorithmProtection(true);

    try {
      ASN1Sequence cmsapSeq = ASN1Sequence.getInstance(cmsAlgoProtAttr.getAttrValues().getObjectAt(0));

      //Get Hash algo
      AlgorithmIdentifier hashAlgoId = AlgorithmIdentifier.getInstance(cmsapSeq.getObjectAt(0));
      sigResult.setCmsapDigestAlgo(hashAlgoId.getAlgorithm());

      //GetSigAlgo
      for (int objIdx = 1; objIdx < cmsapSeq.size(); objIdx++) {
        ASN1Encodable asn1Encodable = cmsapSeq.getObjectAt(objIdx);
        if (asn1Encodable instanceof ASN1TaggedObject) {
          ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(asn1Encodable);
          if (taggedObj.getTagNo() == 1) {
            AlgorithmIdentifier algoId = AlgorithmIdentifier.getInstance(taggedObj, false);
            sigResult.setCmsapSigAlgo(algoId.getAlgorithm());
          }
        }
      }
    }
    catch (Exception e) {
      Logger.getLogger(CMSVerifyUtils.class.getName()).warning("Failed to parse CMSAlgoritmProtection algoritms");
    }
  }

  /**
   * Retrieves Public key parameters from a public key
   *
   * @param pubKey    The public key
   * @param sigResult The data object where result data are stored
   * @throws IOException
   */
  public static void getPkParams(PublicKey pubKey, ExtendedPdfSigValResult sigResult) throws IOException {

    try {
      ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(pubKey.getEncoded()));
      //ASN1Primitive pkObject = din.readObject();
      ASN1Sequence pkSeq = ASN1Sequence.getInstance(din.readObject());
      ASN1BitString keyBits = (ASN1BitString) pkSeq.getObjectAt(1);

      AlgorithmIdentifier algoId = AlgorithmIdentifier.getInstance(pkSeq.getObjectAt(0));
      PublicKeyType pkType = PublicKeyType.getTypeFromOid(algoId.getAlgorithm().getId());
      sigResult.setPkType(pkType);
      sigResult.setPkType(pkType);
      if (pkType.equals(PublicKeyType.EC)) {
        ASN1ObjectIdentifier curveOid = ASN1ObjectIdentifier.getInstance(algoId.getParameters());
        NamedCurve curve = NamedCurveRegistry.get(curveOid);
        sigResult.setNamedEcCurve(curve);
        int totalKeyBits = curve.getKeyLen();
        sigResult.setKeyLength(totalKeyBits);
        return;
      }

      if (pkType.equals(PublicKeyType.RSA)) {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) pubKey;
        sigResult.setKeyLength(rsaPublicKey.getModulus().bitLength());
        return;
      }

    }
    catch (Exception e) {
      Logger.getLogger(CMSVerifyUtils.class.getName()).fine("Illegal public key parameters: " + e.getMessage());
    }
  }

  /**
   * This method extracts the ESSCertID sequence from a SigningCertificate signed CMS attribute. If the signed attribute is of
   * type SigningCertificateV2 (RFC 5035) the returned sequence is ESSCertIDv2. If the signed attribute is of type
   * SigningCertificate (RFC2634 using SHA1 as fixed hash algo) then the returned sequence is of type ESSCertID.
   *
   * @param essSigningCertAttr The signed CMS attribute carried in SignerInfo
   * @return An ASN.1 Sequence holding the sequence of objects in ESSCertID or ESSCertIDv2
   * @throws Exception Any exception caused by input not mathing the assumed processing rules
   */
  public static ASN1Sequence getESSCertIDSequence(Attribute essSigningCertAttr) throws Exception {
    /**
     * Attribute ::= SEQUENCE {
     *   attrType OBJECT IDENTIFIER,
     *   attrValues SET OF AttributeValue }
     */
    ASN1Encodable[] attributeValues = essSigningCertAttr.getAttributeValues();
    ASN1Sequence signingCertificateV2Seq = (ASN1Sequence) attributeValues[0]; //Holds sequence of certs and policy
    /**
     * -- RFC 5035
     * SigningCertificateV2 ::=  SEQUENCE {
     *    certs        SEQUENCE OF ESSCertIDv2,
     *    policies     SEQUENCE OF PolicyInformation OPTIONAL
     * }
     *
     * -- RFC 2634
     * SigningCertificate ::=  SEQUENCE {
     *     certs        SEQUENCE OF ESSCertID,
     *     policies     SEQUENCE OF PolicyInformation OPTIONAL
     * }
     */
    ASN1Sequence sequenceOfESSCertID = (ASN1Sequence) signingCertificateV2Seq.getObjectAt(0); // holds sequence of ESSCertID or ESSCertIDv2
    /**
     * ESSCertIDv2 ::=  SEQUENCE {
     *    hashAlgorithm           AlgorithmIdentifier
     *                    DEFAULT {algorithm id-sha256},
     *    certHash                 Hash,
     *    issuerSerial             IssuerSerial OPTIONAL
     * }
     *
     * ESSCertID ::=  SEQUENCE {
     *      certHash                 Hash,
     *      issuerSerial             IssuerSerial OPTIONAL
     * }
     */
    ASN1Sequence eSSCertIDSeq = (ASN1Sequence) sequenceOfESSCertID.getObjectAt(0); //Holds seq of objects in ESSCertID or ESSCertIDv2
    return eSSCertIDSeq;
  }

  public static boolean checkAlgoritmConsistency(ExtendedPdfSigValResult sigResult) {
    if (sigResult.getSignatureAlgorithm() == null) {
      return false;
    }
    PDFAlgorithmRegistry.PDFSignatureAlgorithmProperties algorithmProperties;
    try {
      algorithmProperties = PDFAlgorithmRegistry.getAlgorithmProperties(
        sigResult.getSignatureAlgorithm());
    }
    catch (NoSuchAlgorithmException e) {
      return false;
    }

    //Ceheck if CML Algoprotection is present.
    if (!sigResult.isCmsAlgorithmProtection()) {
      return true;
    }
    try {
      // Check that the signature algo is equivalent to the algo settings in CMS algo protection
      String cmsAlgoProtAlgoUri = PDFAlgorithmRegistry.getAlgorithmURI(sigResult.getCmsapSigAlgo(), sigResult.getCmsapDigestAlgo());
      if (cmsAlgoProtAlgoUri.equals(sigResult.getSignatureAlgorithm())) {
        return true;
      }
    }
    catch (NoSuchAlgorithmException e) {
      log.debug("Error while comparing CMS algo protection: ", e);
    }
    return false;
  }

  /**
   * converts an X509CertificateHolder object to an X509Certificate object.
   *
   * @param certHolder the cert holder object
   * @return X509Certificate object
   * @throws IOException
   * @throws CertificateException
   */
  public static X509Certificate getCert(X509CertificateHolder certHolder) throws IOException, CertificateException {
    X509Certificate cert;
    ByteArrayInputStream certIs = new ByteArrayInputStream(certHolder.getEncoded());

    try {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      cert = (X509Certificate) cf.generateCertificate(certIs);

    }
    finally {
      certIs.close();
    }

    return cert;
  }

  public static TimeValidationClaims getMatchingTimeValidationClaims(PDFTimeStamp timeStamp, List<TimeValidationClaims> vtList) {
    try {
      Optional<TimeValidationClaims> matchOptional = vtList.stream()
        .filter(verifiedTime -> verifiedTime.getId().equalsIgnoreCase(timeStamp.getTstInfo().getSerialNumber().getValue().toString(16)))
        .findFirst();
      return matchOptional.get();
    }
    catch (Exception ex) {
      return null;
    }
  }

  @Data
  @NoArgsConstructor
  @AllArgsConstructor
  public static class PDFSigCerts {
    private X509Certificate sigCert;
    private List<X509Certificate> chain;
  }

}
