/*
 * Copyright (c) 2021. IDsec Solutions AB
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

package se.idsec.sigval.pdf.pdfstruct;

import java.util.List;

public interface GeneralSafeObjects {

  /**
   * Examine the curent PDF document revision and add object references that are safe to have updated
   * xref pointers to new data without altering the visual content of the PDF document.
   *
   * <p>
   * This process is important in order to allow signed PDF documents to handled by normal readers
   * such as being saved from within an Adobe acrobat reader which may add/alter the DSS object
   * and to alter metadata and/or info object in the document trailer.
   * </p>
   *
   * @param revData
   */
  void addGeneralSafeObjects(PDFDocRevision revData);

}
