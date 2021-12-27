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

package se.swedenconnect.sigval.pdf.pdfstruct;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.pdfbox.cos.*;

import java.util.List;
import java.util.Map;

/**
 * Data class for storing information about a particular incremental update revision of a PDF document
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class PDFDocRevision {
  /** The number of bytes from the beginning of this PDF document that contains this revision */
  private int length;
  /** True if the incremental update of this revision provides a document signature */
  private boolean signature;
  /** True if the incremental update of this revision provides a document timestamp */
  private boolean documentTimestamp;
  /** True if the incremental update of this revision provides a Document Security Store */
  private boolean validDSS;
  /** True if this revision update is considered safe to not provide visual changes to the PDF visual content */
  private boolean safeUpdate;
  /** The object identifier value of the root object of this revision */
  private long rootObjectId;
  /** The COSDocument for this revision providing data about this revision */
  private COSDocument cosDocument;
  /** The root object of this revision */
  private COSObject rootObject;
  /** The trailer of this revision */
  private COSDictionary trailer;
  /** Cross reference map for this revision holding the location of each object identified by each object identifier */
  private Map<COSObjectKey, Long> xrefTable;
  /** A map containing only those cross references that has changed in this revision compared to the previous revision the value
   * array contains the previous and current object location in previous vs current location */
  private Map<COSObjectKey, Long[]> changedXref;
  /** A map containing all new cross references of this revision */
  private Map<COSObjectKey, Long> addedXref;
  /** true if the root object was updated compared with previous revision */
  private boolean rootUpdate;
  /** true if there are other objects with changed cross reference values other than the root object */
  private boolean nonRootUpdate;
  /** true if the root object only holds expected and recognized value types */
  private boolean legalRootObject;
  /** A list of items in the root dictionary that has changed values */
  private List<COSName> changedRootItems;
  /** A list of new items in the root dictionary */
  private List<COSName> addedRootItems;
  /** A list of objects that are considered safe even if they have changed cross references */
  private List<Long> safeObjects;

  /**
   * Limited constructor.
   *
   * <p>This constructor is not complete. Its purpose is limited to create new instances of this object
   * based on some essential initial data. Only selective values are copied into the new instance</p>
   *
   * @param pdfDocRevision source values for a new instance of a revision data object
   */
  public PDFDocRevision(PDFDocRevision pdfDocRevision) {
    this.length = pdfDocRevision.getLength();
    this.signature = pdfDocRevision.isSignature();
    this.documentTimestamp = pdfDocRevision.isDocumentTimestamp();
    this.cosDocument = pdfDocRevision.getCosDocument();
  }
}