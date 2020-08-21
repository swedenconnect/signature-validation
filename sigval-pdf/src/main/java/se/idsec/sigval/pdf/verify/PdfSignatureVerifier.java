package se.idsec.sigval.pdf.verify;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.timestamp.PDFDocTimeStamp;

import java.util.List;

public interface PdfSignatureVerifier {

  /**
   * Verifies the signature on a PDF document
   * @param signature
   * @param pdfDocument
   * @param documentTimestamps
   * @return
   * @throws Exception
   */
  ExtendedPdfSigValResult verifySignature (PDSignature signature, byte[] pdfDocument, List<PDFDocTimeStamp> documentTimestamps) throws Exception;

  List<PDFDocTimeStamp> verifyDocumentTimestamps (List<PDSignature> documentTimestampSignatures, byte[] pdfDocument);

  /**
   * Returns the certificate validator used to validate certificates
   * @return certificate validator
   */
  CertificateValidator getCertificateValidator();

}
