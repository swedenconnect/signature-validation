package se.idsec.sigval.pdf.utils;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTCTime;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import se.idsec.signservice.security.sign.pdf.configuration.PDFObjectIdentifiers;
import se.idsec.sigval.commons.utils.SVAUtils;

import java.io.IOException;
import java.util.*;

/**
 * Utility methods for SVT processing
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFSVAUtils {

  public static final String SIGNATURE_TYPE = "sig";
  public static final String DOC_TIMESTAMP_TYPE = "docts";
  public static final String SVT_TYPE = "svt";
  public static final String UNKNOWN_TYPE = "unknown";
  public static final String PDF_SIG_SUBFILETER_LC = "adbe.pkcs7.detached";
  public static final String CADES_SIG_SUBFILETER_LC = "etsi.cades.detached";
  public static final String TIMESTAMP_SUBFILTER_LC = "etsi.rfc3161";

  public static byte[] getSignatureValueBytes(PDSignature signature, byte[] signedPdf) throws IOException {
    byte[] contents = signature.getContents(signedPdf);
    SignedData signedData = SVAUtils.getSignedDataFromSignature(contents);
    SignerInfo signerInfo = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
    byte[] signatureBytes = signerInfo.getEncryptedDigest().getOctets();
    return signatureBytes;
  }

  public static List<byte[]> getSignatureCertificateList(byte[] pdSignature) throws IOException {
    SignedData signedData = SVAUtils.getSignedDataFromSignature(pdSignature);
    Iterator<ASN1Encodable> iterator = signedData.getCertificates().iterator();
    List<byte[]> certList = new ArrayList<>();
    while (iterator.hasNext()) {
      certList.add(iterator.next().toASN1Primitive().getEncoded("DER"));
    }
    return certList;
  }

  public static String getSignatureType(PDSignature signature, byte[] sigbBytes) {
    String subfilter = signature.getSubFilter().toLowerCase();
    switch (subfilter) {
    case PDF_SIG_SUBFILETER_LC:
    case CADES_SIG_SUBFILETER_LC:
      return SIGNATURE_TYPE;
    case TIMESTAMP_SUBFILTER_LC:
      return SVAUtils.isSVADocTimestamp(sigbBytes) ? SVT_TYPE : DOC_TIMESTAMP_TYPE;
    }
    return UNKNOWN_TYPE;
  }

  public static Date getClaimedSigningTime(Calendar signDate, SignedData signedData) throws Exception {
    //Get first any claimed signing time from signed attributes
    SignerInfo signerInfo = getSignerInfo(signedData);
    ASN1Set signedAttrsSet = signerInfo.getAuthenticatedAttributes();
    for (int i = 0; i < signedAttrsSet.size(); i++) {
      Attribute signedAttr = Attribute.getInstance(signedAttrsSet.getObjectAt(i));
      ASN1ObjectIdentifier attrTypeOID = signedAttr.getAttrType();
      if (attrTypeOID.getId().equals(PDFObjectIdentifiers.ID_SIGNING_TIME)) {
        ASN1Encodable[] attributeValues = signedAttr.getAttributeValues();
        ASN1UTCTime utcTime = ASN1UTCTime.getInstance(attributeValues[0]);
        return utcTime.getDate();
      }
    }
    // Reaching this point means that we found no signing time signed attributes. Using signing time from signature dictionary, if present.
    return signDate == null ? null : signDate.getTime();
  }

  private static SignerInfo getSignerInfo(SignedData signedData) throws Exception {
    ASN1Encodable signerInfoObj = signedData.getSignerInfos().getObjectAt(0);
    SignerInfo signerInfo = SignerInfo.getInstance(signerInfoObj);
    return signerInfo;
  }

}
