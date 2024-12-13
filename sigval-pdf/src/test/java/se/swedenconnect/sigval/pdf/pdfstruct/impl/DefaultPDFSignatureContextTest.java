/*
 * Copyright (c) 2024.  Sweden Connect
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

package se.swedenconnect.sigval.pdf.pdfstruct.impl;

import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.swedenconnect.sigval.pdf.data.PDFConstants;
import se.swedenconnect.sigval.pdf.pdfstruct.PDFDocRevision;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.*;

/**
 * Description
 */
class DefaultPDFSignatureContextTest {


  static byte[] pdfBytes;
  static byte[] hideTextPdfBytes;
   List<PDSignature> signatures = new ArrayList<>();
  List<PDFDocRevision> pdfDocRevisions;

  @BeforeAll
  static void init() throws Exception {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    try(InputStream resourceAsStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("test-doc.pdf")){
      pdfBytes = IOUtils.toByteArray(resourceAsStream);
    }
    try(InputStream resourceAsStream = Thread.currentThread().getContextClassLoader().getResourceAsStream("hideQF1.pdf")){
      hideTextPdfBytes = IOUtils.toByteArray(resourceAsStream);
    }
  }

  @Test
  void testSignatureContext() throws Exception {
    DefaultPDFSignatureContext pdfSignatureContext = new DefaultPDFSignatureContext(hideTextPdfBytes, new DefaultGeneralSafeObjects());
    pdfSignatureContext.getPdfDocRevisions()
    int sdf = 0;
  }

  @Test
  void pdfRevision() throws Exception {
    PDDocument pdDocument = Loader.loadPDF(pdfBytes);
    signatures = pdDocument.getSignatureDictionaries();
    pdfDocRevisions = new ArrayList<>();
    PDFDocRevision lastRevision = this.getRevision(null);
    while (lastRevision != null) {
      final PDFDocRevision lastRevisionClone = new PDFDocRevision(lastRevision);
      this.pdfDocRevisions.add(lastRevisionClone);
      lastRevision = this.getRevision(lastRevisionClone);
    }

    final List<PDDocument> pdDocumentList = new ArrayList<>();

    final List<PDFDocRevision> consolidatedList = new ArrayList<>();

    for (final PDFDocRevision rev : this.pdfDocRevisions) {
      final byte[] revBytes = Arrays.copyOf(this.pdfBytes, rev.getLength());
      try {
        final PDDocument revDoc = Loader.loadPDF(revBytes);
        pdDocumentList.add(revDoc);
        final COSDocument cosDocument = revDoc.getDocument();
        rev.setCosDocument(cosDocument);

        final COSDictionary trailer = cosDocument.getTrailer();
        final long rootObjectId = getRootObjectId(trailer);
        final COSObject rootObject = trailer.getCOSObject(COSName.ROOT);
        final Map<COSObjectKey, Long> xrefTable = cosDocument.getXrefTable();

        rev.setXrefTable(xrefTable);
        rev.setRootObjectId(rootObjectId);
        rev.setRootObject(rootObject);
        rev.setTrailer(trailer);

        consolidatedList.add(rev);
      }
      catch (final Exception ignored) {
        // This means that this was not a valid PDF revision segment and is therefore skipped
      }
    }
    int sdf = 0;
  }

  /**
   * Internal method for obtaining basic revision data for a document revision. Revision data is collected in reverse
   * order starting with the most recent revision. This is a natural con
   *
   * @param priorRevision
   *          Data obtained from the revision after this revision.
   * @return
   */
  private PDFDocRevision getRevision(final PDFDocRevision priorRevision) {
    final int len = priorRevision == null ? this.pdfBytes.length : priorRevision.getLength() - 5;

    final String pdfString = new String(Arrays.copyOf(this.pdfBytes, len), StandardCharsets.ISO_8859_1);
    final int lastIndexOfEoF = pdfString.lastIndexOf("%%EOF");

    if (lastIndexOfEoF == -1) {
      // There are no prior revisions. Return null;
      return null;
    }

    int revisionLen = lastIndexOfEoF + 5;
    final byte firstNl = this.pdfBytes.length > revisionLen ? this.pdfBytes[revisionLen] : 0x00;
    final byte secondNl = this.pdfBytes.length > revisionLen + 1 ? this.pdfBytes[revisionLen + 1] : 0x00;

    revisionLen = firstNl == 0x0a
      ? revisionLen + 1
      : firstNl == 0x0d && secondNl == 0x0a
      ? revisionLen + 2
      : revisionLen;

    boolean revIsSignature = false;
    boolean revIsDocTs = false;
    for (final PDSignature signature : this.signatures) {
      final int[] byteRange = signature.getByteRange();
      if (byteRange[2] + byteRange[3] == revisionLen) {
        revIsSignature = true;
        revIsDocTs = PDFConstants.SUBFILTER_ETSI_RFC3161.equals(signature.getSubFilter());
      }
    }

    return PDFDocRevision.builder()
      .length(revisionLen)
      .signature(revIsSignature)
      .documentTimestamp(revIsDocTs)
      .build();
  }

  /**
   * Obtain the
   *
   * @param trailer
   * @return
   * @throws Exception
   */
  private static long getRootObjectId(final COSDictionary trailer) throws Exception {
    final COSObject root = trailer.getCOSObject(COSName.ROOT);
    return root.getObjectNumber();
  }

}