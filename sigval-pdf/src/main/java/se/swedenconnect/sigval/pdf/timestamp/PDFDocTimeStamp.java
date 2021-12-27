package se.swedenconnect.sigval.pdf.timestamp;

import lombok.Getter;
import se.swedenconnect.sigval.commons.timestamp.TimeStamp;
import se.swedenconnect.sigval.commons.timestamp.TimeStampPolicyVerifier;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

/**
 * This class parse validates and holds the essential information about a PDF document timestamp.
 * This class may be extended to handle specialized forms of document timestamps such as a SVA document timestamp
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class PDFDocTimeStamp extends TimeStamp {

  protected PDSignature documentTimestampSig;

  public PDFDocTimeStamp(PDSignature documentTimestampSig, byte[] pdfDoc, TimeStampPolicyVerifier tsPolicyVerifier) throws Exception {
    super(documentTimestampSig.getContents(pdfDoc), documentTimestampSig.getSignedContent(pdfDoc), tsPolicyVerifier);
    this.documentTimestampSig = documentTimestampSig;
  }

  /**
   * This test checks that the signature and the data signed by this signature is covered by this document timestamp.
   * This test does NOT verify that this signature belongs to this document. The only thing that is tested is
   * that the byte range of this signature falls within the byte range of the document timestamp.
   * <p>
   * Other functions must be used to assure that the signature in question belongs to the same document as the document timestamp.
   *
   * @param signature PDF signature
   * @return true if this signature falls within the byte range of the signed data of this document timestamp.
   */
  public boolean isSignatureCovered(PDSignature signature) {
    try {
      int[] signatureByteRange = signature.getByteRange();
      // Signed data and signature length from start of docuement is the index of the final byte section + length of the final section.
      int sigEndIndex = signatureByteRange[2] + signatureByteRange[3];

      int[] documentTimestampSigByteRange = documentTimestampSig.getByteRange();
      return documentTimestampSigByteRange[1] > sigEndIndex;
    }
    catch (Exception ex) {
      return false;
    }
  }

}
