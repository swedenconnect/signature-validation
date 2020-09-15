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
import se.idsec.sigval.commons.timestamp.TimeStamp;
import se.idsec.sigval.commons.utils.GeneralCMSUtils;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.svt.claims.TimeValidationClaims;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.logging.Logger;

/**
 * Utility methods for CMS verification
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CMSVerifyUtils {

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
    return GeneralCMSUtils.getCMSSignedDataParser(sig.getContents(signedPdfDoc), sig.getSignedContent(signedPdfDoc));
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
      sigResult.setCmsAlgoProtectionDigestAlgo(hashAlgoId.getAlgorithm());

      //GetSigAlgo
      for (int objIdx = 1; objIdx < cmsapSeq.size(); objIdx++) {
        ASN1Encodable asn1Encodable = cmsapSeq.getObjectAt(objIdx);
        if (asn1Encodable instanceof ASN1TaggedObject) {
          ASN1TaggedObject taggedObj = ASN1TaggedObject.getInstance(asn1Encodable);
          if (taggedObj.getTagNo() == 1) {
            AlgorithmIdentifier algoId = AlgorithmIdentifier.getInstance(taggedObj, false);
            sigResult.setCmsAlgoProtectionSigAlgo(algoId.getAlgorithm());
          }
        }
      }
    }
    catch (Exception e) {
      Logger.getLogger(CMSVerifyUtils.class.getName()).warning("Failed to parse CMSAlgoritmProtection algoritms");
    }
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
      String cmsAlgoProtAlgoUri = PDFAlgorithmRegistry.getAlgorithmURI(sigResult.getCmsAlgoProtectionSigAlgo(),
        sigResult.getCmsAlgoProtectionDigestAlgo());
      if (cmsAlgoProtAlgoUri.equals(sigResult.getSignatureAlgorithm())) {
        return true;
      }
    }
    catch (NoSuchAlgorithmException e) {
      log.debug("Error while comparing CMS algo protection: ", e);
    }
    return false;
  }

}
