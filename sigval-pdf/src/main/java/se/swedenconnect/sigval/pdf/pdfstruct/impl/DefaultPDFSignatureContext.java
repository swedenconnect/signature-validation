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
package se.swedenconnect.sigval.pdf.pdfstruct.impl;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSBoolean;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSNumber;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSObjectKey;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import se.swedenconnect.sigval.pdf.data.PDFConstants;
import se.swedenconnect.sigval.pdf.pdfstruct.AcroForm;
import se.swedenconnect.sigval.pdf.pdfstruct.GeneralSafeObjects;
import se.swedenconnect.sigval.pdf.pdfstruct.ObjectArray;
import se.swedenconnect.sigval.pdf.pdfstruct.ObjectValue;
import se.swedenconnect.sigval.pdf.pdfstruct.ObjectValueType;
import se.swedenconnect.sigval.pdf.pdfstruct.PDFDocRevision;
import se.swedenconnect.sigval.pdf.pdfstruct.PDFSignatureContext;

/**
 * Examines a PDF document and gathers context data used to determine document revisions and if any of those revisions
 * may alter the document appearance with respect to document signatures.
 * <p>
 * This class collects data that is used to determine if there is a risk that the document visible content has changed
 * since it was signed.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultPDFSignatureContext implements PDFSignatureContext {

  /** The characters indicating end of a PDF document revision */
  private final static String EOF = "%%EOF";
  /** The bytes of the examined PDF document */
  final byte[] pdfBytes;
  /** Document revisions */
  List<PDFDocRevision> PDFDocRevisions;
  /** Document signatures */
  List<PDSignature> signatures = new ArrayList<>();
  /** Provider of objects safe to update without altering the visual content of the document */
  private final GeneralSafeObjects safeObjectProvider;
  /**
   * True if the document carries non-whitespace content after the last {@code %%EOF} - i.e. it was extended with an
   * incremental update whose terminating {@code %%EOF} is absent. Such trailing bytes are invisible to the revision
   * analysis (which slices on {@code %%EOF}) but are shown by recovering PDF viewers, so no signature can be said to
   * cover the whole physical document. When set, {@link #isCoversWholeDocument(PDSignature)} always returns false.
   */
  private boolean documentExtendedWithIncompleteIncrement = false;

  /**
   * Constructs a DefaultPDFSignatureContext instance.
   * This constructor initializes the context with the provided PDF document bytes
   * and a safe object provider, and extracts revision data from the PDF document.
   *
   * @param pdfBytes
   *          the byte array representing the PDF document
   * @param safeObjectProvider
   *          provider of the logic to identify safe objects in the PDF documents that may be altered without changing
   *          the visual content of the document
   * @throws IOException
   *          if an error occurs while extracting PDF revision data
   */
  public DefaultPDFSignatureContext(final byte[] pdfBytes, final GeneralSafeObjects safeObjectProvider) throws IOException {
    this.pdfBytes = pdfBytes;
    this.safeObjectProvider = safeObjectProvider;
    this.extractPdfRevisionData();
  }

  /** {@inheritDoc} */
  @Override
  public byte[] getSignedDocument(final PDSignature signature) throws IllegalArgumentException {
    try {
      final int idx = this.getSignatureRevisionIndex(signature);
      if (idx < 0) {
        throw new IllegalArgumentException("Signature not found");
      }
      // Note. In previous version, this function returned the doc revision before the signed revision. That is not
      // correct as the signature
      // also signs all data of the current revision. The current way is compatible with the view function of Adobe
      // reader
      return Arrays.copyOf(this.pdfBytes, this.PDFDocRevisions.get(idx).getLength());
    }
    catch (final Exception ex) {
      throw new IllegalArgumentException("Error extracting signed version", ex);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSignatureExtendedByNonSafeUpdates(final PDSignature signature) throws IllegalArgumentException {
    try {
      final int idx = this.getSignatureRevisionIndex(signature);
      if (idx == -1) {
        throw new IllegalArgumentException("Signature not found");
      }
      for (int i = idx; i < this.PDFDocRevisions.size() - 1; i++) {
        // Loop as long as index indicates that there is a later revision (index < revisions -1)
        final PDFDocRevision pdfDocRevision = this.PDFDocRevisions.get(i + 1);
        if (!pdfDocRevision.isSignature() && !pdfDocRevision.isValidDSS()) {
          // A later revision exist that is NOT a signature, document timestamp)
          // Return true if this update is not a safe update
          return !pdfDocRevision.isSafeUpdate();
        }
      }
      // We did not find any later revisions that are not a signature or document timestamp
      return false;
    }
    catch (final Exception ex) {
      throw new IllegalArgumentException("Error examining signature extensions", ex);
    }
  }

  private int getSignatureRevisionIndex(final PDSignature signature) throws IllegalArgumentException {
    try {
      final int[] byteRange = signature.getByteRange();
      final int len = byteRange[2] + byteRange[3];

      for (int i = 0; i < this.PDFDocRevisions.size(); i++) {
        final PDFDocRevision revision = this.PDFDocRevisions.get(i);
        if (revision.getLength() == len) {
          // Get the bytes of the prior revision
          return i;
        }
      }
      return -1;
    }
    catch (final Exception ex) {
      throw new IllegalArgumentException("Error examining signature revision", ex);
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isCoversWholeDocument(final PDSignature signature) throws IllegalArgumentException {
    final int revisionIndex = this.getSignatureRevisionIndex(signature);
    if (revisionIndex == -1) {
      throw new IllegalArgumentException("The specified signature was not found in the document");
    }
    if (this.documentExtendedWithIncompleteIncrement) {
      // Non-whitespace content follows the last %%EOF: the document was extended with an incremental update whose
      // terminating %%EOF is absent. That content forms no recognized revision but is rendered by recovering viewers,
      // so no signature can cover the whole physical document - regardless of which revision this signature is in.
      return false;
    }
    if (revisionIndex == this.PDFDocRevisions.size() - 1) {
      // The signature is the last revision
      return true;
    }

    for (int i = revisionIndex + 1; i < this.PDFDocRevisions.size(); i++) {
      final PDFDocRevision nextRevision = this.PDFDocRevisions.get(i);
      if (!nextRevision.isSafeUpdate()) {
        return false;
      }
    }
    return true;
  }

  /** The {@code %%EOF} marker as bytes. */
  private static final byte[] EOF_BYTES = EOF.getBytes(StandardCharsets.US_ASCII);

  /**
   * Maximum number of bytes permitted after the terminating {@code %%EOF}. A well-formed PDF ends with {@code %%EOF}
   * and at most a line terminator, so the terminating marker must fall within this window of end-of-file; anything
   * beyond it is treated as an extension. Searching only this tail also bounds the work to a small constant regardless
   * of document size (no whole-document copy, no unbounded scan).
   */
  private static final int MAX_BYTES_AFTER_LAST_EOF = 4096;

  /**
   * Returns true if the document carries content after the terminating {@code %%EOF}, i.e. it was extended with an
   * incremental update whose {@code %%EOF} is absent. The terminating {@code %%EOF} is located only within the last
   * {@link #MAX_BYTES_AFTER_LAST_EOF} bytes: if it is not there, the document has a large trailing extension and is
   * flagged without scanning it; otherwise only the small remainder after it is checked, permitting only PDF whitespace
   * (NUL, HT, LF, FF, CR, SPACE).
   *
   * @return true if the document has content after its terminating {@code %%EOF}
   */
  private boolean hasNonWhitespaceContentAfterLastEof() {
    final int lastEof = this.lastEofInTail(MAX_BYTES_AFTER_LAST_EOF);
    if (lastEof == -1) {
      // No terminating %%EOF within the permitted tail window: the document was extended past its %%EOF (or has none).
      return true;
    }
    for (int i = lastEof + EOF_BYTES.length; i < this.pdfBytes.length; i++) {
      if (!isPdfWhitespace(this.pdfBytes[i])) {
        return true;
      }
    }
    return false;
  }

  /**
   * Returns the byte index of the last {@code %%EOF} occurring within the final {@code maxTailBytes} bytes of the
   * document, or -1 if there is none within that window. Bounding the search to the tail avoids copying the document
   * and keeps the work constant regardless of document size.
   *
   * @param maxTailBytes the number of trailing bytes (before the marker) to search
   * @return the index of the last {@code %%EOF} within the tail window, or -1
   */
  private int lastEofInTail(final int maxTailBytes) {
    final int stop = Math.max(0, this.pdfBytes.length - EOF_BYTES.length - maxTailBytes);
    for (int i = this.pdfBytes.length - EOF_BYTES.length; i >= stop; i--) {
      if (matchesAt(this.pdfBytes, i, EOF_BYTES)) {
        return i;
      }
    }
    return -1;
  }

  /** Returns true if {@code pattern} occurs in {@code data} starting at {@code offset}. */
  private static boolean matchesAt(final byte[] data, final int offset, final byte[] pattern) {
    if (offset < 0 || offset + pattern.length > data.length) {
      return false;
    }
    for (int j = 0; j < pattern.length; j++) {
      if (data[offset + j] != pattern[j]) {
        return false;
      }
    }
    return true;
  }

  /** PDF whitespace characters per ISO 32000-1: NUL, HT, LF, FF, CR and SPACE. */
  private static boolean isPdfWhitespace(final byte b) {
    return b == 0x00 || b == 0x09 || b == 0x0a || b == 0x0c || b == 0x0d || b == 0x20;
  }

  /** {@inheritDoc} */
  @Override
  public void applyValidatedSignature(final PDSignature signature) {
    final int idx;
    try {
      idx = this.getSignatureRevisionIndex(signature);
    }
    catch (final Exception ex) {
      // The signature is not present in this document. Nothing to upgrade.
      return;
    }
    if (idx < 0) {
      return;
    }
    final PDFDocRevision revision = this.PDFDocRevisions.get(idx);
    // Only a revision that is structurally a signature or document timestamp may be granted the lenient rules, and
    // only once its signature/timestamp has been validated to a trusted anchor by the caller. Idempotent.
    if (revision.isSignature() || revision.isDocumentTimestamp()) {
      revision.setSafeUpdate(revision.isSafeUpdateLenient());
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<PDFDocRevision> getPdfDocRevisions() {
    return this.PDFDocRevisions;
  }

  /** {@inheritDoc} */
  @Override
  public List<PDSignature> getSignatures() {
    return this.signatures;
  }

  /**
   * Extracts PDF revision data by analyzing the signatures and revision segments of a PDF document.
   * This method processes the PDF bytes to extract information such as signature dictionaries,
   * cross-reference tables, root objects, and trailer objects for each revision.
   * It consolidates, sorts, and validates the revisions, ensuring a structured representation
   * of the document's historical states. Invalid revisions are skipped during the processing.
   *
   * @throws IOException if an error occurs while handling the PDF document or its revisions
   */
  private void extractPdfRevisionData() throws IOException {

    // Get all pdf document signatures and document timestamps
    final PDDocument pdfDoc = Loader.loadPDF(this.pdfBytes);
    this.signatures = pdfDoc.getSignatureDictionaries();
    pdfDoc.close();
    this.PDFDocRevisions = new ArrayList<>();
    PDFDocRevision lastRevision = this.getRevision(null);
    while (lastRevision != null) {
      final PDFDocRevision lastRevisionClone = new PDFDocRevision(lastRevision);
      this.PDFDocRevisions.add(lastRevisionClone);
      lastRevision = this.getRevision(lastRevisionClone);
    }

    final List<PDDocument> pdDocumentList = new ArrayList<>();

    final List<PDFDocRevision> consolidatedList = new ArrayList<>();
    for (final PDFDocRevision rev : this.PDFDocRevisions) {
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

    // Get consolidated and sorted list of PDF revisions
    this.PDFDocRevisions = consolidatedList.stream()
      .sorted(Comparator.comparingInt(value -> value.getLength()))
      .collect(Collectors.toList());

    // Detect an incremental update whose terminating %%EOF was removed: any non-whitespace content after the last
    // %%EOF. Such trailing bytes form no recognized revision (revisions are sliced on %%EOF) yet recovering viewers
    // still render them, so when present no signature can cover the whole physical document.
    this.documentExtendedWithIncompleteIncrement = this.hasNonWhitespaceContentAfterLastEof();

    PDFDocRevision lastRevData = null;
    for (final PDFDocRevision revData : this.PDFDocRevisions) {
      this.getXrefUpdates(revData, lastRevData);
      lastRevData = revData;
    }

    // Close documents
    pdDocumentList.stream().forEach(pdDocument -> {
      try {
        pdDocument.close();
      }
      catch (final IOException e) {
        e.printStackTrace();
      }
    });

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
    final int lastIndexOfEoF = pdfString.lastIndexOf(EOF);
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
   * Retrieves the object ID of the root object from the given PDF trailer dictionary.
   *
   * @param trailer The trailer dictionary of a PDF file, containing information about the structure of the document.
   * @return The object ID of the root object if it exists, otherwise 0.
   * @throws Exception If the root object cannot be retrieved or an error occurs during processing.
   */
  private static long getRootObjectId(final COSDictionary trailer) throws Exception {
    final COSObject root = trailer.getCOSObject(COSName.ROOT);
    return root.getKey().getNumber();
  }

  /**
   * Analyzes and identifies changes between the current document revision and the previous revision by inspecting
   * cross-reference tables, root dictionary updates, and object validity. The method categorizes these changes
   * as either safe or unsafe updates based on predefined validation rules.
   *
   * @param revData the current {@link PDFDocRevision} containing the details of the active document revision
   *                including cross-reference tables and root dictionary.
   * @param lastRevData the previous {@link PDFDocRevision} representing the last revision of the document. This
   *                    parameter is used for comparison to identify changes. If null, all cross-references in
   *                    the current revision are treated as new.
   */
  private void getXrefUpdates(final PDFDocRevision revData, final PDFDocRevision lastRevData) {
    revData.setLegalRootObject(true);
    revData.setRootUpdate(false);
    revData.setNonRootUpdate(false);
    final Map<COSObjectKey, Long> lastTable = lastRevData == null ? new HashMap<>() : lastRevData.getXrefTable();
    final Map<COSObjectKey, Long[]> changedXref = new HashMap<>();
    final Map<COSObjectKey, Long> addedXref = new HashMap<>();
    final Map<COSObjectKey, Long> xrefTable = revData.getXrefTable();

    // Find new and changed xref values
    xrefTable.keySet().forEach(cosObjectKey -> {
      final Long newValue = xrefTable.get(cosObjectKey);
      if (lastTable.containsKey(cosObjectKey)) {
        final Long lastValue = lastTable.get(cosObjectKey);
        if (lastValue.longValue() != newValue.longValue()) {
          changedXref.put(cosObjectKey, new Long[] { lastValue, newValue });
        }
      }
      else {
        addedXref.put(cosObjectKey, newValue);
      }
    });
    revData.setChangedXref(changedXref);
    revData.setAddedXref(addedXref);

    changedXref.keySet().forEach(cosObjectKey -> {
      if (cosObjectKey.getNumber() == revData.getRootObjectId()) {
        revData.setRootUpdate(true);
      }
      if (cosObjectKey.getNumber() != revData.getRootObjectId()) {
        revData.setNonRootUpdate(true);
      }
    });

    // We will also detect objects referenced from safe COSName. We will allow updates to these objects.
    // These are /AcroForm /OpenAction and /Font and non root objects that are considered valid below.
    //
    // The signature-dependent part (whether a signature/timestamp revision may leniently add annotation/field
    // changes) is computed twice below - once strict, once lenient - via isSafeReferenceUpdate. Here we only gather
    // the signature-INDEPENDENT base safe objects: non-root objects absent in both revisions, plus the root-referenced
    // and general safe objects collected further down.
    final List<Long> baseSafeObjects = new ArrayList<>();

    for (COSObjectKey objectKey : changedXref.keySet()) {
      // Non-root objects that are absent in both the old and new revision are safe regardless of signature status.
      if (objectKey.getNumber() != revData.getRootObjectId()
          && (lastRevData == null || lastRevData.getCosDocument().getObjectFromPool(objectKey) == null)
          && revData.getCosDocument().getObjectFromPool(objectKey) == null) {
        baseSafeObjects.add(objectKey.getNumber());
      }
    }

    // Check which root dictionary items that are actually changed and which items in the root that has been added
    // This change check is limited to known COSNames. If any other COSName appear in the root, it is treated as an
    // illegal root dictionary.
    // Illegal doesn't necessary mean that it's illegal, but it is not trusted to provide non-visual changes.
    final List<COSName> changedRootItems = new ArrayList<>();
    final List<COSName> addedRootItems = new ArrayList<>();
    if (revData.isRootUpdate()) {
      final COSBase baseObject = revData.getRootObject().getObject();
      if (baseObject instanceof final COSDictionary rootDic) {
        revData.setLegalRootObject(true);
        final COSObject lastRoot = lastRevData.getRootObject();
        rootDic.entrySet().forEach(cosNameCOSBaseEntry -> {
          final COSName key = cosNameCOSBaseEntry.getKey();
          final ObjectValue value = new ObjectValue(cosNameCOSBaseEntry.getValue());
          if (lastRoot.getObject() instanceof COSDictionary){
            final ObjectValue lastValue = new ObjectValue(((COSDictionary)lastRoot.getObject()).getItem(key));
            // Detect changes in root item values
            if (lastValue.getType() != ObjectValueType.Null) {
              if (lastValue.getType().equals(ObjectValueType.Other)) {
                revData.setLegalRootObject(false);
              }
              else {
                if (!value.matches(lastValue)) {
                  changedRootItems.add(key);
                }
              }
            }
            else {
              addedRootItems.add(key);
            }
            // Look for safe objects
            addSafeObjects(key, cosNameCOSBaseEntry.getValue(), baseSafeObjects, revData.getCosDocument());
          } else {
            revData.setLegalRootObject(false);
          }
        });
      }
      else {
        revData.setLegalRootObject(false);
      }
    }
    revData.setChangedRootItems(changedRootItems);
    revData.setAddedRootItems(addedRootItems);
    revData.setSafeObjects(baseSafeObjects);

    // Check changed root items for unsupported changes.
    // In this implementation only the Acroform are allowed to have changed content in the root dictionary
    final boolean unsupportedRootItemUpdate = revData.getChangedRootItems().stream()
        .anyMatch(name -> !name.equals(COSName.ACRO_FORM));

    // Append the safeObjectList with other known safe objects. This mutates revData.getSafeObjects() (baseSafeObjects).
    this.safeObjectProvider.addGeneralSafeObjects(revData);

    /*
     * A new revision is considered safe with regard to not containing visual data changes when added after a signature
     * if:
     *
     * - Changes to objects in the xref list is only applied to objects references in the root that are considered safe.
     * These are: o Objects containing the content of AcroForms o Objects holding Font inside DR dictionary inside
     * Acroform o Objects referenced under OpenAction in the root o Other safe ojects according to the GeneralSafeObject
     * interface implementation
     *
     * We compute two conclusions from the same rules: a strict one (the lenient signature/timestamp annotation rules
     * are NOT applied) and a lenient one (they are). The effective safeUpdate starts strict; applyValidatedSignature
     * promotes it to the lenient value only once this revision's signature/timestamp has been validated as trusted.
     */
    revData.setSafeUpdate(this.isSafeReferenceUpdate(revData, lastRevData, changedXref,
        revData.getSafeObjects(), unsupportedRootItemUpdate, false));
    revData.setSafeUpdateLenient(this.isSafeReferenceUpdate(revData, lastRevData, changedXref,
        revData.getSafeObjects(), unsupportedRootItemUpdate, true));

    /*
     * A revision is considered a valid DSS update if:
     *
     * - There is an update to the root object - There is no change to any other pre-existing xref other than to the
     * root object - The updated root object has legal content - There are no changed root items - There is 1 or 2 new
     * root item where DSS object is mandatory and Extension is optional - The new item in the root is a pointer to a
     * DSS object or DSS + Extension object
     */
    revData.setValidDSS(
        revData.isRootUpdate()
            && revData.isSafeUpdate()
            && revData.isLegalRootObject()
            && revData.getChangedRootItems().isEmpty()
            && (revData.getAddedRootItems().size() == 1 && addedRootItemsContains(revData.getAddedRootItems(), "DSS")
            || revData.getAddedRootItems().size() == 2 && addedRootItemsContains(revData.getAddedRootItems(), "DSS", "Extensions")));

  }

  /**
   * Determines whether all changed non-root cross references of a revision are covered by safe objects, given a choice
   * of whether the lenient signature/timestamp annotation rules apply.
   *
   * <p>The base safe objects (signature-independent) are provided by the caller. This method adds the annotation-based
   * safe objects computed for the requested {@code signature} leniency and then verifies that no changed non-root
   * object falls outside the resulting safe set.</p>
   *
   * @param revData the current revision
   * @param lastRevData the previous revision (may be null for the first revision)
   * @param changedXref the changed cross references of this revision
   * @param baseSafeObjects the signature-independent safe objects
   * @param unsupportedRootItemUpdate whether the root dictionary carries an unsupported changed item
   * @param signature whether lenient signature/timestamp annotation rules apply
   * @return true if the revision is a safe (non-visual) update under the given leniency
   */
  private boolean isSafeReferenceUpdate(final PDFDocRevision revData, final PDFDocRevision lastRevData,
      final Map<COSObjectKey, Long[]> changedXref, final List<Long> baseSafeObjects,
      final boolean unsupportedRootItemUpdate, final boolean signature) {

    final List<Long> safeObjects = new ArrayList<>(baseSafeObjects);
    for (final COSObjectKey objectKey : changedXref.keySet()) {
      if (objectKey.getNumber() != revData.getRootObjectId()) {
        final COSObject oldObject = lastRevData == null ? null : lastRevData.getCosDocument().getObjectFromPool(objectKey);
        final COSObject newObject = revData.getCosDocument().getObjectFromPool(objectKey);
        if (oldObject == null || newObject == null) {
          // Both-null objects are already in the base safe set; a single-null change is not a safe annotation change.
          continue;
        }
        if (isOnlyNewAnnotations(oldObject, newObject, signature)) {
          safeObjects.add(objectKey.getNumber());
        }
      }
    }

    final boolean unsafeRefupdate = changedXref.keySet().stream()
        .map(COSObjectKey::getNumber)
        .anyMatch(id -> id != revData.getRootObjectId() && !safeObjects.contains(id));

    return !unsupportedRootItemUpdate && !unsafeRefupdate && revData.isLegalRootObject();
  }

  /**
   * Checks whether the difference between two COSObjects is only the addition of new invisible annotations.
   *
   * @param oldObject the original COSObject representing the old state
   * @param newObject the updated COSObject representing the new state
   * @return true if the updated COSObject only contains new invisible annotations, false otherwise
   */
  private boolean isOnlyNewAnnotations(COSObject oldObject, COSObject newObject, boolean signature) {
    // Check if the changed object is itself an annotation, if so, go directly to check if the annotatioin is safe
    if (isAnnotationObject(oldObject) && isAnnotationObject(newObject)) {
      // consider it safe if the *new* annotation is clearly non-visual
       return isInvisibleAnnotation(newObject, signature);
    }

    if (!(oldObject.getObject() instanceof final COSDictionary oldDict) || !(newObject.getObject() instanceof final COSDictionary newDict)) {
      return false;
    }

    // Compare all entries except /Annots
    for (COSName key : oldDict.keySet()) {
      if (!key.equals(COSName.ANNOTS)) {
        final COSBase oldDictItem = oldDict.getItem(key);
        final COSBase newDictItem = newDict.getItem(key);
        if (oldDictItem == null && newDictItem == null) {
          // This is legal. Both items are null
          continue;
        }
        if (newDictItem == null || oldDictItem == null) {
          log.debug("Non root object is changed from content to null or from null to content");
          return false;
        }
        if (!new ObjectValue(oldDictItem).matches(new ObjectValue(newDictItem))) {
          if (key.equals(COSName.FIELDS)) {
            if (fieldsOnlyContainsNewSafeAnnotations(oldDictItem, newDictItem, signature)) {
              log.trace("Fields dictionary contains only new safe annotations");
              continue;
            }
          }
          log.debug("Non root object update non annotation content mismatch: {} New value: {}", oldDictItem,
              newDictItem);
          return false; // The references are not equal
        }
        log.trace("Non root object update non annotation content match: {}", newDictItem);
      }
    }

    // Forbid adding any new non-/Annots keys
    boolean hasTypedAnnots = false;
    for (COSName key : newDict.keySet()) {
      if (!oldDict.containsKey(key)) {
        if (key.equals(COSName.ANNOTS)) {
          continue;
        }
        if (key.equals(COSName.TYPE) && COSName.ANNOT.equals(newDict.getCOSName(COSName.TYPE))) {
          hasTypedAnnots = true;
          continue;
        }
        log.debug("Non root object added an unsafe non annotation item: {}", key);
        return false;
      }
    }

    // Check that /Annots in the new object contains all items from the old object + only new ones
    COSArray oldAnnots = oldDict.getCOSArray(COSName.ANNOTS);
    COSArray newAnnots = newDict.getCOSArray(COSName.ANNOTS);

    if (newAnnots == null) {
      if (hasTypedAnnots) {
        log.debug("New annotation list is null, but /Type is Annot. This is an annotation change");
        return true;
      }
      // if newAnnots is null, then this is an error because this function is only called if there is an xref change.
      // Since there are no new annotations, the change must be something else.
      log.debug("New annotation list is null, therefore the change is not an annotation change");
      return false;
    }
    if (oldAnnots != null && !containsAll(newAnnots, oldAnnots)) {
      // If there are old annotations but the new annotations don't contain all old annotations, something was removed.
      log.debug("New annotation list does not contain all old annotations, an annotation was removed");
      return false;
    }

    // Ensure new /Annots entries are valid (e.g., invisible signatures)
    for (COSBase annot : newAnnots) {
      if (oldAnnots == null || !arrayContains(oldAnnots, annot)) {
        if (!isInvisibleAnnotation(annot, signature)) {
          log.debug("New annotation is not invisible: {}", annot);
          return false; // New annotation is not invisible
        }
      }
    }

    return true;
  }

  private boolean fieldsOnlyContainsNewSafeAnnotations(final COSBase oldDictItem, final COSBase newDictItem, boolean signature) {

    COSBase newCosObject = new COSObject(newDictItem).getObject();
    COSBase oldCosObject = new COSObject(oldDictItem).getCOSObject();

    // TODO Currently all changes are allowed for signature. None for non signatures. Add logic if deemed necessary.
    return signature;

  }

  private boolean isAnnotationObject(COSBase b) {
    if (b instanceof COSObject) b = ((COSObject) b).getObject();
    return (b instanceof COSDictionary)
        && COSName.ANNOT.equals(((COSDictionary) b).getCOSName(COSName.TYPE));
  }

  // Returns true iff the annotation is clearly non-visual for our purposes.
  // Conservative policy: if anything is ambiguous → return false (potentially visible).
  private boolean isInvisibleAnnotation(COSBase annot, boolean signature) {
    // --- 0) Resolve to annotation dictionary ---
    COSDictionary a = null;
    if (annot instanceof COSObject) {
      COSBase obj = ((COSObject) annot).getObject();
      if (obj instanceof COSDictionary) a = (COSDictionary) obj;
    } else if (annot instanceof COSDictionary) {
      a = (COSDictionary) annot;
    }
    if (a == null) {
      // Unknown / not a dict → don't claim "invisible"
      return false;
    }

    // --- 1) Read /F flags (visibility/print behavior) ---
    int flags = 0;
    COSBase f = a.getDictionaryObject(COSName.F);
    if (f instanceof COSNumber) flags = ((COSNumber) f).intValue();

    final boolean HIDDEN    = (flags & 2)  != 0; // do not display or print, regardless of type
    final boolean PRINT     = (flags & 4)  != 0; // print with page
    final boolean NO_VIEW   = (flags & 32) != 0; // do not display on screen (may still print)

    // NOTE: The Invisible flag (/F bit 1) is deliberately NOT treated as hiding the annotation.
    // Per ISO 32000-1, 12.5.3 (Table 165), Invisible only suppresses rendering of annotations whose
    // subtype is non-standard AND for which the viewer has no annotation handler. Standard, renderable
    // subtypes (Square, FreeText, Circle, Line, Stamp, Polygon, ...) are still painted by viewers when
    // Invisible is set - so a full-page white Square plus FreeText overlays flagged /F 1 would be
    // displayed by every viewer while masquerading as a "safe, invisible" update. Only Hidden and NoView
    // reliably suppress on-screen display for all subtypes.
    if (HIDDEN || NO_VIEW) {
      return true;
    }

    // --- 2) Subtype (used for a few safe special cases) ---
    String subtype = "";
    COSName subName = a.getCOSName(COSName.SUBTYPE);
    if (subName != null) subtype = subName.getName();

    // /Popup never renders by itself (only the parent markup summons it)
    if ("Popup".equals(subtype)) {
      return true;
    }

    // --- 3) /Rect (require presence before considering "zero-area") ---
    // Using a small epsilon for robustness to float encoding noise.
    final float EPS = 0.001f;

    COSArray rect = a.getCOSArray(COSName.RECT);
    boolean hasRect = rect != null && rect.size() == 4;

    float x1 = hasRect ? getFloatFromCOSArray(rect, 0) : 0f;
    float y1 = hasRect ? getFloatFromCOSArray(rect, 1) : 0f;
    float x2 = hasRect ? getFloatFromCOSArray(rect, 2) : 0f;
    float y2 = hasRect ? getFloatFromCOSArray(rect, 3) : 0f;

    // Defensive: treat NaN/Inf as visibly non-zero
    if (!hasRect || !isFinite(x1) || !isFinite(y1) || !isFinite(x2) || !isFinite(y2)) {
      return false;
    }

    boolean zeroArea = Math.abs(x2 - x1) <= EPS && Math.abs(y2 - y1) <= EPS;

    // --- 4) Appearance stream present? (/AP /N) ---
    // If a normal appearance exists, we assume it's potentially visible (we don't parse it here).
    boolean hasAppearance = false;
    COSBase ap = a.getDictionaryObject(COSName.AP);
    if (ap instanceof COSDictionary) {
      hasAppearance = ((COSDictionary) ap).getDictionaryObject(COSName.N) != null;
    }

    // --- 5) Effective border width: from /Border or /BS /W (default 1) ---
    float borderWidth = 1f;

    COSArray border = a.getCOSArray(COSName.BORDER); // [hRadius vRadius width]
    if (border != null && border.size() >= 3 && border.get(2) instanceof COSNumber) {
      borderWidth = ((COSNumber) border.get(2)).floatValue();
    } else {
      COSBase bs = a.getDictionaryObject(COSName.BS);
      if (bs instanceof COSDictionary) {
        COSBase w = ((COSDictionary) bs).getDictionaryObject(COSName.W);
        if (w instanceof COSNumber) borderWidth = ((COSNumber) w).floatValue();
      }
    }
    if (!isFinite(borderWidth)) borderWidth = 1f;

    // --- 6) Clearly non-visual cases (short-circuit to true) ---

    // 6a) Invisible link: no appearance, effectively zero border, and zero-area rect
    if ("Link".equals(subtype) && !hasAppearance && borderWidth <= EPS && zeroArea) {
      return true;
    }

    // 6b-0) Zero-area signature/timestamp field:
    // A zero-area Widget renders nothing - its appearance is scaled into an empty /Rect - so it cannot alter the
    // visual content regardless of the Print flag or the presence of an (empty) appearance stream. This is recognized
    // as non-visual independently of trust, so that legitimate invisible signature and document-timestamp fields never
    // depend on the lenient (validated-signature) path below. This matters for SVT re-issuance: an older SVT whose
    // key/algorithm no longer validates at present time still leaves its invisible field non-visual under the strict
    // rules, so document coverage does not break merely because the old SVT is no longer independently trusted.
    // Scoped to Widget because signature/timestamp fields are always Widgets and Widgets render strictly within their
    // /Rect (unlike Line/Ink/Polygon, whose geometry may extend outside /Rect).
    if ("Widget".equals(subtype) && zeroArea) {
      return true;
    }

    // 6b) Signature widget (common for doc timestamps):
    // /Subtype /Widget, /FT /Sig. A visible widget is only accepted when this revision is a validated
    // (trusted) signature or document timestamp - see the trust-gating in getXrefUpdates/applyValidatedSignature.
    if ("Widget".equals(subtype)) {
      //COSBase ft = a.getDictionaryObject(COSName.FT);
      if (signature) {
        return true;
      }
    }

    // 6c) Print-equivalence shortcut:
    // If not set to print, has no appearance, and occupies zero area → won't alter printed pages.
    if (!PRINT && !hasAppearance && zeroArea) {
      return true;
    }

    // --- 7) Otherwise: treat as potentially visible ---
    return false;
  }

  // Small helper to guard float values
  private static boolean isFinite(float v) {
    return !Float.isNaN(v) && !Float.isInfinite(v);
  }

  // Helper method: Safely extract a float from a COSArray at a given index
  private float getFloatFromCOSArray(COSArray array, int index) {
    if (index < array.size()) {
      COSBase base = array.get(index);
      if (base instanceof COSNumber) {
        return ((COSNumber) base).floatValue();
      }
    }
    return 0.0f; // Default to 0.0 if the value is missing or invalid
  }

  // Checks if 'superset' contains all elements in 'subset'
  private boolean containsAll(COSArray superset, COSArray subset) {
    if (subset == null) return true;
    if (superset == null) return false;
    for (COSBase item : subset) {
      if (!arrayContains(superset, item)) {
        return false;
      }
    }
    return true;
  }

  // True if array contains an entry that refers to the same indirect object as `element`,
  // or (for non-indirects) an equal value.
  private boolean arrayContains(COSArray array, COSBase element) {
    if (array == null) return false;

    COSObjectKey targetKey = getRefKey(element);
    if (targetKey != null) {
      for (COSBase item : array) {
        COSObjectKey k = getRefKey(item);
        if (targetKey.equals(k)) return true;
      }
      return false;
    }

    // Non-indirect: fall back to value equality (lightweight)
    COSBase elem = deref(element);
    for (COSBase item : array) {
      if (cosValueEquals(deref(item), elem)) return true;
    }
    return false;
  }

  private COSBase deref(COSBase b) {
    return (b instanceof COSObject) ? ((COSObject) b).getObject() : b;
  }

  private COSObjectKey getRefKey(COSBase b) {
    if (b instanceof COSObject) {
      COSObject o = (COSObject) b;
      COSObjectKey k = o.getKey();
      return (k != null) ? k : new COSObjectKey(o.getObjectNumber(), o.getGenerationNumber());
    }
    return null;
  }

  private static final float NUM_EPS = 1e-4f;

  private boolean numbersEqual(COSNumber a, COSNumber b) {
    if (a == b) return true;
    if (a == null || b == null) return false;

    boolean aIsInt = a instanceof org.apache.pdfbox.cos.COSInteger;
    boolean bIsInt = b instanceof org.apache.pdfbox.cos.COSInteger;

    if (aIsInt && bIsInt) {
      return a.longValue() == b.longValue();
    }

    float fa = a.floatValue();
    float fb = b.floatValue();
    if (Float.isNaN(fa) || Float.isNaN(fb) || Float.isInfinite(fa) || Float.isInfinite(fb)) return false;
    return Math.abs(fa - fb) <= NUM_EPS;
  }

  private boolean cosValueEquals(COSBase a, COSBase b) {
    if (a == b) return true;
    if (a == null || b == null) return false;

    // Names
    if (a instanceof COSName && b instanceof COSName) return a.equals(b);

    // Numbers (int/float tolerant)
    if (a instanceof COSNumber && b instanceof COSNumber) {
      return numbersEqual((COSNumber) a, (COSNumber) b);
    }

    // Strings (byte-wise)
    if (a instanceof org.apache.pdfbox.cos.COSString && b instanceof org.apache.pdfbox.cos.COSString) {
      return java.util.Arrays.equals(
          ((org.apache.pdfbox.cos.COSString) a).getBytes(),
          ((org.apache.pdfbox.cos.COSString) b).getBytes()
      );
    }

    // Booleans / Null
    if (a instanceof COSBoolean && b instanceof COSBoolean) {
      return ((COSBoolean) a).getValue() == ((COSBoolean) b).getValue();
    }
    if (a instanceof org.apache.pdfbox.cos.COSNull && b instanceof org.apache.pdfbox.cos.COSNull) {
      return true;
    }

    // Arrays / Dicts are handled by your containsAll(...) recursion; keep this shallow here.
    return a.equals(b);
  }

  private static boolean addedRootItemsContains(final List<COSName> addedRootItems, final String... matchNames) {
    if (addedRootItems == null) {
      return false;
    }
    for (final String matchName : matchNames) {
      if (addedRootItems.stream()
        .noneMatch(cosName -> cosName.getName().equalsIgnoreCase(matchName))) {
        return false;
      }
    }
    return true;
  }

  private static void addSafeObjects(final COSName key, final COSBase value, final List<Long> safeObjects, final COSDocument cosDocument) {
    if (key == null || value == null) {
      return;
    }
    if (key.equals(COSName.ACRO_FORM)) {
      if (value instanceof COSObject) {
        safeObjects.add(((COSObject) value).getObjectNumber());
      }
      final AcroForm acroForm = new AcroForm(value, cosDocument);
      final long acroFormFont = acroForm.getObjectRef("DR", "Font");
      if (acroFormFont > -1) {
        safeObjects.add(acroFormFont);
      }

    }
    if (key.equals(COSName.OPEN_ACTION)) {
      if (value instanceof COSArray) {
        final ObjectArray cosArray = new ObjectArray((COSArray) value);
        final List<ObjectValue> objectList = cosArray.getValues().stream()
          .filter(objectValue -> objectValue.getType().equals(ObjectValueType.COSObject))
          .collect(Collectors.toList());
        if (objectList.size() == 1) {
          safeObjects.add((long) objectList.get(0).getValue());
        }
      }
    }
  }

}
