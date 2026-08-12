/*
 * Copyright (c) 2026. Sweden Connect
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
package se.swedenconnect.sigval.pdf.pdfstruct;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.junit.jupiter.api.Test;

import se.swedenconnect.sigval.pdf.data.PDFConstants;
import se.swedenconnect.sigval.pdf.pdfstruct.impl.DefaultGeneralSafeObjects;
import se.swedenconnect.sigval.pdf.pdfstruct.impl.DefaultPDFSignatureContext;

import java.io.InputStream;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression tests for the PDF post-signature update ("safe update" / coverage) analysis, exercised against real
 * documents on disk. These tests operate purely on {@link DefaultPDFSignatureContext}, which is a structural analysis
 * and requires no trust anchors, so the production-signed fixtures can be examined without their trust chains.
 *
 * <p>Fixtures:</p>
 * <ul>
 *   <li>{@code hello-prod-full.pdf} - a legitimately signed + SVT-timestamped document to which a forged incremental
 *       revision was appended: a full-page white {@code Square} plus {@code FreeText} overlays, all flagged
 *       {@code /F 1} (Invisible). This is the Bug 4 (Invisible-flag) attack.</li>
 *   <li>{@code hello-signed-prod2.pdf} - the clean control: signed and SVT-timestamped, no post-signing tampering.</li>
 * </ul>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
class PdfCoverageRegressionTest {

  /**
   * Bug 4 - the Invisible-flag fix. The forged final revision of {@code hello-prod-full.pdf} adds standard,
   * renderable annotations (Square, FreeText) flagged only {@code /F 1}. Those must NOT be treated as invisible, so the
   * revision must be an unsafe update and the signature must no longer cover the whole document.
   */
  @Test
  void forgedInvisibleOverlay_isUnsafeUpdate_andBreaksCoverage() throws Exception {
    final DefaultPDFSignatureContext context =
        new DefaultPDFSignatureContext(readFixture("/hello-prod-full.pdf"), new DefaultGeneralSafeObjects());

    final List<PDFDocRevision> revisions = context.getPdfDocRevisions();
    assertEquals(5, revisions.size(), "expected base + signature + 2 SVT timestamps + forged revision");

    // The forged content is the last incremental update, and it is NOT a signature/timestamp revision.
    final PDFDocRevision forgedRevision = revisions.get(revisions.size() - 1);
    assertFalse(forgedRevision.isSignature(), "the forged revision must not be a signature");
    assertFalse(forgedRevision.isDocumentTimestamp(), "the forged revision must not be a document timestamp");
    assertFalse(forgedRevision.isSafeUpdate(),
        "the forged full-page Square + FreeText overlays (/F 1) must make the revision an UNSAFE update - "
            + "if this fails, the Invisible-flag short-circuit has been reintroduced (Bug 4)");

    // End to end: the document signature must no longer cover the whole document.
    final PDSignature documentSignature = firstDocumentSignature(context);
    assertFalse(context.isCoversWholeDocument(documentSignature),
        "the appended forged revision must break full-document coverage for the signature");
  }

  /**
   * The clean control plus the zero-area rule. {@code hello-signed-prod2.pdf} ends at its SVT document timestamp, whose
   * field is invisible (zero-area). That revision must be a safe update under the STRICT rules (no trust upgrade is
   * applied because we do not run the validator here), and the signature must cover the whole document.
   */
  @Test
  void legitimateSvtStampedDocument_isSafeAndCoversWholeDocument() throws Exception {
    final DefaultPDFSignatureContext context =
        new DefaultPDFSignatureContext(readFixture("/hello-signed-prod2.pdf"), new DefaultGeneralSafeObjects());

    final List<PDFDocRevision> revisions = context.getPdfDocRevisions();
    assertEquals(3, revisions.size(), "expected base + signature + SVT timestamp");

    // The SVT document timestamp is the last revision. Its zero-area field must pass the strict rules on its own.
    final PDFDocRevision svtRevision = revisions.get(revisions.size() - 1);
    assertTrue(svtRevision.isDocumentTimestamp(), "the last revision should be the SVT document timestamp");
    assertTrue(svtRevision.isSafeUpdate(),
        "the SVT timestamp's invisible (zero-area) field must be a safe update under the STRICT rules - "
            + "this is what lets SVT re-issuance keep full coverage when an older SVT is no longer trusted");

    final PDSignature documentSignature = firstDocumentSignature(context);
    assertTrue(context.isCoversWholeDocument(documentSignature),
        "a cleanly signed and SVT-timestamped document must cover the whole document (no false positive)");
  }

  /**
   * Trust-gating. The document signature revision of {@code hello-signed-prod2.pdf} adds a VISIBLE signature widget, so
   * that revision is NOT a safe update under the strict rules. Only after the signature is registered as validated
   * (via {@link DefaultPDFSignatureContext#applyValidatedSignature}) may it be treated leniently and become safe.
   */
  @Test
  void visibleSignatureWidget_requiresValidatedSignatureUpgrade() throws Exception {
    final DefaultPDFSignatureContext context =
        new DefaultPDFSignatureContext(readFixture("/hello-signed-prod2.pdf"), new DefaultGeneralSafeObjects());

    final List<PDFDocRevision> revisions = context.getPdfDocRevisions();
    // Index 0 = base, index 1 = the document signature revision (carrying the visible signature widget).
    final PDFDocRevision signatureRevision = revisions.get(1);
    assertTrue(signatureRevision.isSignature(), "revision 1 should be the document signature");

    assertFalse(signatureRevision.isSafeUpdate(),
        "before the signature is validated, its revision (with a visible signature widget) must be UNSAFE under the "
            + "strict rules - i.e. lenient treatment must not be granted structurally");

    // Register the signature as validated to a trusted anchor.
    context.applyValidatedSignature(firstDocumentSignature(context));

    assertTrue(signatureRevision.isSafeUpdate(),
        "after the signature validates to trust, its revision must be upgraded to the lenient conclusion (safe)");
  }

  /** Returns the first document signature that is not an RFC 3161 document timestamp (i.e. the actual signer). */
  private static PDSignature firstDocumentSignature(final DefaultPDFSignatureContext context) {
    return context.getSignatures().stream()
        .filter(sig -> !PDFConstants.SUBFILTER_ETSI_RFC3161.equals(sig.getSubFilter()))
        .findFirst()
        .orElseThrow(() -> new IllegalStateException("No document signature found in fixture"));
  }

  private static byte[] readFixture(final String resource) throws Exception {
    try (InputStream is = PdfCoverageRegressionTest.class.getResourceAsStream(resource)) {
      assertNotNull(is, "Test fixture not found on classpath: " + resource);
      return is.readAllBytes();
    }
  }
}
