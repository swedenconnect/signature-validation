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
    // We will allow updates to referenced objects if the update is signature
    // or timestamp.
    final List<Long> safeObjects = new ArrayList<>();


    for (COSObjectKey objectKey : changedXref.keySet()) {
      // Validation specific to non-root updates
      if (objectKey.getNumber() != revData.getRootObjectId()) { // Non-root object
        COSObject oldObject = lastRevData.getCosDocument().getObjectFromPool(objectKey);
        COSObject newObject = revData.getCosDocument().getObjectFromPool(objectKey);
        if (oldObject == null && newObject == null) {
          // Safe object. Both are null
          safeObjects.add(objectKey.getNumber());
          continue;
        }
        if (oldObject == null || newObject == null) {
          // Not considered safe non-root object
          continue;
        }
        // Check if the only difference is a new annotation in /Annots
        if (isOnlyNewAnnotations(oldObject, newObject)) {
          // Safe object. Only safe annotation changes
          safeObjects.add(objectKey.getNumber());
        }
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
            addSafeObjects(key, cosNameCOSBaseEntry.getValue(), safeObjects, revData.getCosDocument());
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
    revData.setSafeObjects(safeObjects);

    // Check changed root items for unsupported changes.
    // In this implementation only the Acroform are allowed to have changed content in the root dictionary
    final boolean unsupportedRootItemUpdate = revData.getChangedRootItems().stream()
        .anyMatch(name -> !name.equals(COSName.ACRO_FORM));

    // Append the safeObjectList with other known safe objects
    this.safeObjectProvider.addGeneralSafeObjects(revData);

    // Check changed cross references against safe objects
    final boolean unsafeRefupdate = revData.getChangedXref().keySet().stream()
        .map(COSObjectKey::getNumber)
        .anyMatch(id -> id != revData.getRootObjectId() &&
            !safeObjects.contains(id));

    /*
     * A new revision is considered safe with regard to not containing visual data changes when added after a signature
     * if:
     *
     * - Changes to objects in the xref list is only applied to objects references in the root that are considered safe.
     * These are: o Objects containing the content of AcroForms o Objects holding Font inside DR dictionary inside
     * Acroform o Objects referenced under OpenAction in the root o Other safe ojects according to the GeneralSafeObject
     * interface implementation
     */
    revData.setSafeUpdate(
        !unsupportedRootItemUpdate
            && !unsafeRefupdate
            && revData.isLegalRootObject());

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
   * Checks whether the difference between two COSObjects is only the addition of new invisible annotations.
   *
   * @param oldObject the original COSObject representing the old state
   * @param newObject the updated COSObject representing the new state
   * @return true if the updated COSObject only contains new invisible annotations, false otherwise
   */
  private boolean isOnlyNewAnnotations(COSObject oldObject, COSObject newObject) {
    // Check if the changed object is itself an annotation, if so, go directly to check if the annotatioin is safe
    if (isAnnotationObject(oldObject) && isAnnotationObject(newObject)) {
      // consider it safe if the *new* annotation is clearly non-visual
       return isInvisibleAnnotation(newObject);
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
          log.debug("Non root object update non annotation content mismatch: {} New value: {}", oldDictItem,
              newDictItem);
          return false; // The references are not equal
        }
        log.trace("Non root object update non annotation content match: {}", newDictItem);
      }
    }

    // Forbid adding any new non-/Annots keys
    for (COSName key : newDict.keySet()) {
      if (!key.equals(COSName.ANNOTS) && !oldDict.containsKey(key)) {
        log.debug("Non root object added an unsafe non annotation item: {}", key);
        return false;
      }
    }

    // Check that /Annots in the new object contains all items from the old object + only new ones
    COSArray oldAnnots = oldDict.getCOSArray(COSName.ANNOTS);
    COSArray newAnnots = newDict.getCOSArray(COSName.ANNOTS);

    if (newAnnots == null) {
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
        if (!isInvisibleAnnotation(annot)) {
          log.debug("New annotation is not invisible: {}", annot);
          return false; // New annotation is not invisible
        }
      }
    }

    return true;
  }

  private boolean isAnnotationObject(COSBase b) {
    if (b instanceof COSObject) b = ((COSObject) b).getObject();
    return (b instanceof COSDictionary)
        && COSName.ANNOT.equals(((COSDictionary) b).getCOSName(COSName.TYPE));
  }

  // Returns true iff the annotation is clearly non-visual for our purposes.
  // Conservative policy: if anything is ambiguous → return false (potentially visible).
  private boolean isInvisibleAnnotation(COSBase annot) {
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

    final boolean INVISIBLE = (flags & 1)  != 0; // viewer should not display
    final boolean HIDDEN    = (flags & 2)  != 0; // do not display/print
    final boolean PRINT     = (flags & 4)  != 0; // print with page
    final boolean NO_VIEW   = (flags & 32) != 0; // do not display on screen

    // If the viewer is instructed not to show it on screen, treat as non-visual for screen mode.
    if (INVISIBLE || HIDDEN || NO_VIEW) {
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

    // 6b) Signature widget (common for doc timestamps):
    // /Subtype /Widget, /FT /Sig
    if ("Widget".equals(subtype)) {
      COSBase ft = a.getDictionaryObject(COSName.FT);
      if (ft instanceof COSName && COSName.SIG.equals(ft)) {
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
