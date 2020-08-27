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

package se.idsec.sigval.pdf.verify.policy;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class PdfSignatureContext {

  /** The characters indicating end of a PDF document revision */
  private final static String EOF = "%%EOF";
  /** The bytes of a PDF document */
  @Getter byte[] pdfBytes;
  /** Document revisions in reverse order (last revision first) */
  @Getter List<PdfDocRevision> pdfDocRevisions;
  /** Document signatures */
  @Getter List<PDSignature> signatures = new ArrayList<>();

  /**
   * Constructor
   * @param pdfBytes the bytes of a PDF document
   * @throws IOException if theis docuemnt is not a well formed PDF document
   */
  public PdfSignatureContext(byte[] pdfBytes) throws IOException {
    this.pdfBytes = pdfBytes;
    getDocRevisions();
  }

  /**
   * Extracts the bytes of the PDF document that was signed by the provided signature
   * @param signature pdf signature
   * @return the byes signed by the provided signature
   * @throws IllegalArgumentException if the signature is not found or no signed data can be located
   */
  public byte[] getSignedDocument(PDSignature signature) throws IllegalArgumentException {
    try {
      int idx = getSignatureRevisionIndex(signature);
      if (idx == -1){
        throw new IllegalArgumentException("Signature not found");
      }
      return Arrays.copyOf(pdfBytes, pdfDocRevisions.get(idx + 1).getLength());
    }
    catch (Exception ex) {
      throw new IllegalArgumentException("Error extracting signed version", ex);
    }
  }

  /**
   * Check if the pdf docuement was updated after this signature was added to the document, where the new update is not
   * a new signature or document timestamp.
   *
   * <p>An update to a PDF docuemtn applied after the PDF document was signed invalidates any existing signture unless the
   * update is not a new signature or document timestamp</p>
   *
   * <p>Some validation policies may require that any new signatures or document timestamps must be trusted and verified
   * for it to be an acceptable update to a signed docuement</p>
   *
   * @param signature the PDF signature
   * @return true if the provided signature was updated by a non signature update
   * @throws IllegalArgumentException on failure to test if the signature was updated by a non signature update
   */
  public boolean isSignatureExtendedByNonSignatureUpdates(PDSignature signature) throws IllegalArgumentException {
    try {
      int idx = getSignatureRevisionIndex(signature);
      if (idx == -1){
        throw new IllegalArgumentException("Signature not found");
      }
      for (int i = idx ; i > 0 ; i-- ){
        // Loop as long as index indicates that there is a later revision (i>0)
        if (!pdfDocRevisions.get(i-1).isSignature()){
          //A later revsion exist that is NOT a signature or document timestamp
          return true;
        }
      }
      // We did not find any later revisions that are not a signature or document timestamp
      return false;
    } catch (Exception ex){
      throw new IllegalArgumentException("Error examining signature extensions", ex);
    }
  }

  private int getSignatureRevisionIndex(PDSignature signature) throws IllegalArgumentException {
    try {
      int[] byteRange = signature.getByteRange();
      int len = byteRange[2] + byteRange[3];

      for (int i = 0; i < pdfDocRevisions.size(); i++) {
        PdfDocRevision revision = pdfDocRevisions.get(i);
        if (revision.getLength() == len) {
          // Get the bytes of the prior revision
          return i;
        }
      }
      return -1;
    } catch (Exception ex){
      throw new IllegalArgumentException("Error examining signature revision", ex);
    }
  }

  private void getDocRevisions() throws IOException {

    PDDocument pdfDoc = PDDocument.load(pdfBytes);
    signatures = pdfDoc.getSignatureDictionaries();
    pdfDoc.close();
    pdfDocRevisions = new ArrayList<>();
    PdfDocRevision lastRevision = getRevision(null);
    while (lastRevision != null) {
      PdfDocRevision lastRevisionClone = new PdfDocRevision(lastRevision);
      pdfDocRevisions.add(lastRevisionClone);
      lastRevision = getRevision(lastRevisionClone);
    }
  }

  private PdfDocRevision getRevision(PdfDocRevision priorRevision) {
    PdfDocRevision docRevision = new PdfDocRevision();
    int len = priorRevision == null ? pdfBytes.length : priorRevision.length - 5;

    String pdfString = new String(Arrays.copyOf(pdfBytes, len), StandardCharsets.ISO_8859_1);
    int lastIndexOfEoF = pdfString.lastIndexOf(EOF);
    if (lastIndexOfEoF == -1) {
      // There are no prior revisions. Return null;
      return null;
    }

    int revisionLen = lastIndexOfEoF + 5;
    byte firstNl = pdfBytes.length > revisionLen ? pdfBytes[revisionLen] : 0x00;
    byte secondNl = pdfBytes.length > revisionLen + 1 ? pdfBytes[revisionLen + 1] : 0x00;

    revisionLen = firstNl == 0x0a
      ? revisionLen + 1
      : firstNl == 0x0d && secondNl == 0x0a
      ? revisionLen + 2
      : revisionLen;

    int finalLastIndexOfEof = revisionLen;
    boolean signatureOrTimestamp = signatures.stream()
      .filter(signature -> {
        int[] byteRange = signature.getByteRange();
        return byteRange[2] + byteRange[3] == finalLastIndexOfEof;
      })
      .findFirst().isPresent();

    return new PdfDocRevision(revisionLen, signatureOrTimestamp);
  }

  @NoArgsConstructor
  @AllArgsConstructor
  @Data
  public static class PdfDocRevision {
    int length;
    boolean signature;

    public PdfDocRevision(PdfDocRevision pdfDocRevision) {
      this.length = pdfDocRevision.getLength();
      this.signature = pdfDocRevision.isSignature();
    }
  }

}
