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
package se.idsec.sigval.pdf.pdfstruct.impl;

import lombok.Setter;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import se.idsec.sigval.pdf.data.PDFConstants;
import se.idsec.sigval.pdf.pdfstruct.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Examines a PDF document and gathers context data used to determine document revisions and if any of those
 * revisions may alter the document appearance with respect to document signatures.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
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
   * Constructor
   *
   * @param pdfBytes the bytes of a PDF document
   * @param safeObjectProvider provider of the logic to identify safe objects in the PDF documents that may be altered
   *                           without changing the visual content of the document
   * @throws IOException if theis docuemnt is not a well formed PDF document
   */
  public DefaultPDFSignatureContext(final byte[] pdfBytes, GeneralSafeObjects safeObjectProvider) throws IOException {
    this.pdfBytes = pdfBytes;
    this.safeObjectProvider = safeObjectProvider;
    extractPdfRevisionData();
  }

  /** {@inheritDoc} */
  @Override public byte[] getSignedDocument(final PDSignature signature) throws IllegalArgumentException {
    try {
      int idx = getSignatureRevisionIndex(signature);
      if (idx < 0) {
        throw new IllegalArgumentException("Signature not found");
      }
      // Note. In previous version, this function returned the doc revision before the signed revision. That is not correct as the signature
      // also signs all data of the current revision. The current way is compatible with the view function of Adobe reader
      return Arrays.copyOf(pdfBytes, PDFDocRevisions.get(idx).getLength());
    }
    catch (Exception ex) {
      throw new IllegalArgumentException("Error extracting signed version", ex);
    }
  }

  /** {@inheritDoc} */
  @Override public boolean isSignatureExtendedByNonSafeUpdates(final PDSignature signature) throws IllegalArgumentException {
    try {
      int idx = getSignatureRevisionIndex(signature);
      if (idx == -1) {
        throw new IllegalArgumentException("Signature not found");
      }
      for (int i = idx; i < PDFDocRevisions.size() - 1; i++) {
        // Loop as long as index indicates that there is a later revision (index < revisions -1)
        PDFDocRevision pdfDocRevision = PDFDocRevisions.get(i + 1);
        if (!pdfDocRevision.isSignature() && !pdfDocRevision.isValidDSS()) {
          // A later revision exist that is NOT a signature, document timestamp)
          // Return true if this update is not a safe update
          return !pdfDocRevision.isSafeUpdate();
        }
      }
      // We did not find any later revisions that are not a signature or document timestamp
      return false;
    }
    catch (Exception ex) {
      throw new IllegalArgumentException("Error examining signature extensions", ex);
    }
  }

  private int getSignatureRevisionIndex(final PDSignature signature) throws IllegalArgumentException {
    try {
      int[] byteRange = signature.getByteRange();
      int len = byteRange[2] + byteRange[3];

      for (int i = 0; i < PDFDocRevisions.size(); i++) {
        PDFDocRevision revision = PDFDocRevisions.get(i);
        if (revision.getLength() == len) {
          // Get the bytes of the prior revision
          return i;
        }
      }
      return -1;
    }
    catch (Exception ex) {
      throw new IllegalArgumentException("Error examining signature revision", ex);
    }
  }

  /** {@inheritDoc} */
  @Override public boolean isCoversWholeDocument(final PDSignature signature) throws IllegalArgumentException {
    int revisionIndex = getSignatureRevisionIndex(signature);
    if (revisionIndex == -1) {
      throw new IllegalArgumentException("The specified signature was not found in the document");
    }
    if (revisionIndex == PDFDocRevisions.size() - 1) {
      // The signature is the last revision
      return true;
    }

    for (int i = revisionIndex + 1; i < PDFDocRevisions.size(); i++) {
      PDFDocRevision nextRevision = PDFDocRevisions.get(i);
      if (!nextRevision.isSafeUpdate()) {
        return false;
      }
    }
    return true;
  }

  /** {@inheritDoc} */
  @Override public List<PDFDocRevision> getPdfDocRevisions() {
    return PDFDocRevisions;
  }

  /** {@inheritDoc} */
  @Override public List<PDSignature> getSignatures() {
    return signatures;
  }

  /**
   * Internal function used to extract data about all document revisions of the current PDF document
   *
   * @throws IOException on error loading PDF document data
   */
  private void extractPdfRevisionData() throws IOException {

    // Get all pdf document signatures and document timestamps
    PDDocument pdfDoc = PDDocument.load(pdfBytes);
    signatures = pdfDoc.getSignatureDictionaries();
    pdfDoc.close();
    PDFDocRevisions = new ArrayList<>();
    PDFDocRevision lastRevision = getRevision(null);
    while (lastRevision != null) {
      PDFDocRevision lastRevisionClone = new PDFDocRevision(lastRevision);
      PDFDocRevisions.add(lastRevisionClone);
      lastRevision = getRevision(lastRevisionClone);
    }

    List<PDDocument> pdDocumentList = new ArrayList<>();

    List<PDFDocRevision> consolidatedList = new ArrayList<>();
    for (PDFDocRevision rev : PDFDocRevisions) {
      byte[] revBytes = Arrays.copyOf(pdfBytes, rev.getLength());
      try {
        PDDocument revDoc = PDDocument.load(revBytes);
        pdDocumentList.add(revDoc);
        COSDocument cosDocument = revDoc.getDocument();
        rev.setCosDocument(cosDocument);
        List<COSObject> objects = cosDocument.getObjects();
        COSDictionary trailer = cosDocument.getTrailer();
        long rootObjectId = getRootObjectId(trailer);
        COSObject rootObject = objects.stream()
          .filter(cosObject -> cosObject.getObjectNumber() == rootObjectId)
          .findFirst().get();
        Map<COSObjectKey, Long> xrefTable = cosDocument.getXrefTable();

        rev.setXrefTable(xrefTable);
        rev.setRootObjectId(rootObjectId);
        rev.setRootObject(rootObject);
        rev.setTrailer(trailer);

        consolidatedList.add(rev);
      }
      catch (Exception ignored) {
        // This means that this was not a valid PDF revision segment and is therefore skipped
      }
    }

    // Get consolidated and sorted list of PDF revisions
    PDFDocRevisions = consolidatedList.stream()
      .sorted(Comparator.comparingInt(value -> value.getLength()))
      .collect(Collectors.toList());

    PDFDocRevision lastRevData = null;
    for (PDFDocRevision revData : PDFDocRevisions) {
      getXrefUpdates(revData, lastRevData);
      lastRevData = revData;
    }

    // Close documents
    pdDocumentList.stream().forEach(pdDocument -> {
      try {
        pdDocument.close();
      }
      catch (IOException e) {
        e.printStackTrace();
      }
    });

  }

  /**
   * Internal method for obtaining basic revision data for a document revision. Revision data is collected in reverse order starting with
   * the most recent revision. This is a natural con
   *
   * @param priorRevision Data obtained from the revision after this revision.
   * @return
   */
  private PDFDocRevision getRevision(final PDFDocRevision priorRevision) {
    int len = priorRevision == null ? pdfBytes.length : priorRevision.getLength() - 5;

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

    boolean revIsSignature = false;
    boolean revIsDocTs = false;
    for (PDSignature signature : signatures) {
      int[] byteRange = signature.getByteRange();
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
   * @param trailer
   * @return
   * @throws Exception
   */
  private static long getRootObjectId(COSDictionary trailer) throws Exception {
    COSObject root = trailer.getCOSObject(COSName.ROOT);
    return root.getObjectNumber();
  }

  private void getXrefUpdates(PDFDocRevision revData, PDFDocRevision lastRevData) {
    revData.setLegalRootObject(true);
    revData.setRootUpdate(false);
    revData.setNonRootUpdate(false);
    Map<COSObjectKey, Long> lastTable = lastRevData == null ? new HashMap<>() : lastRevData.getXrefTable();
    Map<COSObjectKey, Long[]> changedXref = new HashMap<>();
    Map<COSObjectKey, Long> addedXref = new HashMap<>();
    Map<COSObjectKey, Long> xrefTable = revData.getXrefTable();

    // Find new and changed xref values
    xrefTable.keySet().forEach(cosObjectKey -> {
      Long newValue = xrefTable.get(cosObjectKey);
      if (lastTable.containsKey(cosObjectKey)) {
        Long lastValue = lastTable.get(cosObjectKey);
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

    changedXref.keySet().stream().forEach(cosObjectKey -> {
      if (cosObjectKey.getNumber() == revData.getRootObjectId()) {
        revData.setRootUpdate(true);
      }
      if (cosObjectKey.getNumber() != revData.getRootObjectId()) {
        revData.setNonRootUpdate(true);
      }
    });

    // Check which root dictionaly items that are actually changed and which items in the root that has been added
    // This change check is limited to known COSNames. If any other COSName appear in the root, it is treated as an illegal root dictionary.
    // Illegal doesn't necessary mean that is is illegal, but it is not trusted to provide non visual changes.
    List<COSName> changedRootItems = new ArrayList<>();
    List<COSName> addedRootItems = new ArrayList<>();
    // We will also detect objects referenced from safe COSName in the root. We will allow updates to these objects.
    // These are /AcroForm /OpenAction and /Font. We will allow updates to referenced objects if the update is signature or timestamp.
    List<Long> safeObjects = new ArrayList<>();
    if (revData.isRootUpdate()) {
      COSBase baseObject = revData.getRootObject().getObject();
      if (baseObject instanceof COSDictionary) {
        revData.setLegalRootObject(true);
        COSObject lastRoot = lastRevData.getRootObject();
        COSDictionary rootDic = (COSDictionary) baseObject;
        rootDic.entrySet().stream().forEach(cosNameCOSBaseEntry -> {
          COSName key = cosNameCOSBaseEntry.getKey();
          ObjectValue value = new ObjectValue(cosNameCOSBaseEntry.getValue());
          ObjectValue lastValue = new ObjectValue(lastRoot.getItem(key));
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

        });
      }
      else {
        revData.setLegalRootObject(false);
      }
    }
    revData.setChangedRootItems(changedRootItems);
    revData.setAddedRootItems(addedRootItems);
    revData.setSafeObjects(safeObjects);

    //Check changed root items for unsupported changes.
    //In this implementation only the Acroform are allowed to have changed content in the root dictionary
    boolean unsupportedRootItemUpdate = revData.getChangedRootItems().stream()
      .anyMatch(name -> !name.equals(COSName.ACRO_FORM));

    // Append the safeObjectList with other known safe objects
    safeObjectProvider.addGeneralSafeObjects(revData);

    // Check changed cross references against safe objects
    boolean unsafeRefupdate = revData.getChangedXref().keySet().stream()
      .map(COSObjectKey::getNumber)
      .anyMatch(id ->
        id != revData.getRootObjectId() &&
          !safeObjects.contains(id)
      );

    /**
     * A new revision is considered safe with regard to not containing visual data changes when added after a signature if:
     *
     *   - Changes to objects in the xref list is only applied to objects references in the root that are considered safe. These are:
     *     o Objects containing the content of AcroForms
     *     o Objects holding Font inside DR dictionary inside Acroform
     *     o Objects referenced under OpenAction in the root
     *     o Other safe ojects according to the GeneralSafeObject interface implementation
     */
    revData.setSafeUpdate(
      !unsupportedRootItemUpdate
        && !unsafeRefupdate
        && revData.isLegalRootObject()
    );

    /**
     * A revision is considered a valid DSS update if:
     *
     *   - There is an update to the root object
     *   - There is no change to any other pre-existing xref other than to the root object
     *   - The updated root object has legal content
     *   - There are no changed root items
     *   - There is 1 or 2 new root item where DSS object is mandatory and Extension is optional
     *   - The new item in the root is a pointer to a DSS object or DSS + Extension object
     */
    revData.setValidDSS(
      revData.isRootUpdate()
        && revData.isSafeUpdate()
        && revData.isLegalRootObject()
        && revData.getChangedRootItems().size() == 0
        && (
          (revData.getAddedRootItems().size() == 1 && addedRootItemsContains(revData.getAddedRootItems(), "DSS"))
          ||(revData.getAddedRootItems().size() == 2 && addedRootItemsContains(revData.getAddedRootItems(), "DSS", "Extensions")))
    );

  }

  private static boolean addedRootItemsContains(List<COSName> addedRootItems, String... matchNames) {
    if (addedRootItems == null) return false;
    for (String matchName : matchNames){
      if(addedRootItems.stream()
        .noneMatch(cosName -> cosName.getName().equalsIgnoreCase(matchName))) {
        return false;
      }
    }
    return true;
  }

  private static void addSafeObjects(COSName key, COSBase value, List<Long> safeObjects, COSDocument cosDocument) {
    if (key == null || value == null) {
      return;
    }
    if (key.equals(COSName.ACRO_FORM)) {
      if (value instanceof COSObject) {
        safeObjects.add(((COSObject) value).getObjectNumber());
      }
      AcroForm acroForm = new AcroForm(value, cosDocument);
      long acroFormFont = acroForm.getObjectRef("DR", "Font");
      if (acroFormFont > -1)
        safeObjects.add(acroFormFont);

    }
    if (key.equals(COSName.OPEN_ACTION)) {
      if (value instanceof COSArray) {
        ObjectArray cosArray = new ObjectArray((COSArray) value);
        List<ObjectValue> objectList = cosArray.getValues().stream()
          .filter(objectValue -> objectValue.getType().equals(ObjectValueType.COSObject))
          .collect(Collectors.toList());
        if (objectList.size() == 1) {
          safeObjects.add((long) objectList.get(0).getValue());
        }
      }
    }
  }

}
