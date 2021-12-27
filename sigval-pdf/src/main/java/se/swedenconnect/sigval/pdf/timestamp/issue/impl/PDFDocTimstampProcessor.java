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
package se.swedenconnect.sigval.pdf.timestamp.issue.impl;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import se.idsec.signservice.security.sign.pdf.PDFBoxSignatureInterface;
import se.idsec.signservice.security.sign.pdf.document.VisibleSignatureImage;
import se.idsec.signservice.security.sign.pdf.utils.PDFSigningProcessor;
import se.swedenconnect.sigval.pdf.data.PDFConstants;
import se.swedenconnect.sigval.pdf.timestamp.issue.PDFDocTimestampSignatureInterface;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * This class provides a PDF signing processor that provides the basic functionality to use a
 * {@link org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface} implementation to generate PDF
 * signature data.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Setter
@AllArgsConstructor
@Builder
@Slf4j
public class PDFDocTimstampProcessor {

  /**
   * Add a document timestamp with an SVT token to the supplied PDF document.
   *
   * @param pdfDocumentBytes          the document to sign
   * @param pdfSignatureProvider the PDFBox signature provider
   * @param svt signature validation token
   * @return the extended document
   * @throws SignatureException for signature errors
   */
  public static Result createSVTSealedPDF(
    final byte[] pdfDocumentBytes,
    final String svt,
    final PDFDocTimestampSignatureInterface pdfSignatureProvider
  ) throws SignatureException {

    PDDocument pdfDocument = null;

    try {
      pdfDocument = PDDocument.load(pdfDocumentBytes);
      pdfSignatureProvider.setSvt(svt);
      // Create signature dictionary
      PDSignature signature = new PDSignature();
      signature.setType(COSName.DOC_TIME_STAMP);
      signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      signature.setSubFilter(COSName.getPDFName(PDFConstants.SUBFILTER_ETSI_RFC3161));

      // Set reserved space for the time stamp signature
      int lengthEstimate = getLengthestimate(pdfSignatureProvider.getCertificateChain(), pdfSignatureProvider.getSvt());
      SignatureOptions options = new SignatureOptions();
      options.setPreferredSignatureSize(lengthEstimate);

      // No certification allowed because /Reference is not allowed in signature directory
      // see ETSI EN 319 142-1 Part 1 and ETSI TS 102 778-4
      // http://www.etsi.org/deliver/etsi_en%5C319100_319199%5C31914201%5C01.01.00_30%5Cen_31914201v010100v.pdf
      // http://www.etsi.org/deliver/etsi_ts/102700_102799/10277804/01.01.01_60/ts_10277804v010101p.pdf

      // register signature dictionary and sign interface
      pdfDocument.addSignature(signature,pdfSignatureProvider, options);

      // Execute signing operation and get resulting PDF document.
      //
      final ByteArrayOutputStream output = new ByteArrayOutputStream();
      // This is where the signing process is invoked
      pdfDocument.saveIncremental(output);
      pdfDocument.close();

      return Result.builder()
        .document(output.toByteArray())
        .cmsSignedData(pdfSignatureProvider.getCmsSignedData())
        .cmsSignedAttributes(pdfSignatureProvider.getCmsSignedAttributes())
        .build();
    }
    catch (IOException e) {
      final String msg = String.format("Failed to create PDF document timestamp - %s", e.getMessage());
      log.error("{}", msg);
      throw new SignatureException(msg, e);
    }
    finally {
      try {
        // If the document already has been closed this is a no-op.
        pdfDocument.close();
      }
      catch (IOException e) {
      }
    }
  }

  /**
   * Calculate the minimum reserved space for the SVA timestamp as lenthg of SVA + Length of certs + 2000
   *
   * @param certList Array of signing certificates
   * @param sva       Signature validation assertion JWT
   * @return reserve length
   */
  private static int getLengthestimate(List<X509Certificate> certList, String sva) {
    int certLenTotal = 0;
    for (X509Certificate cert : certList) {
      try {
        certLenTotal += cert.getEncoded().length;
      }
      catch (CertificateEncodingException e) {
        e.printStackTrace();
      }
    }
    int svaLen = sva.getBytes(StandardCharsets.UTF_8).length;
    int reservedLen = svaLen + certLenTotal + 2000;
    return reservedLen;
  }

  /**
   * Result object for
   * {@link PDFSigningProcessor#signPdfDocument(PDDocument, PDFBoxSignatureInterface, long, VisibleSignatureImage)}.
   */
  @Getter
  @Builder
  public static class Result {

    /**
     * The signed document.
     *
     * @return the signed document
     */
    private byte[] document;

    /**
     * The CMS SignedData.
     *
     * @return the CMS SignedData
     */
    private byte[] cmsSignedData;

    /**
     * The signed attributes.
     *
     * @return the signed attributes
     */
    private byte[] cmsSignedAttributes;
  }

}
