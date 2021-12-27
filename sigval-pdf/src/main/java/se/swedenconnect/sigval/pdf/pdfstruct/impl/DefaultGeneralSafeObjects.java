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

package se.swedenconnect.sigval.pdf.pdfstruct.impl;

import java.util.Arrays;
import java.util.List;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.sigval.pdf.pdfstruct.Dictionary;
import se.swedenconnect.sigval.pdf.pdfstruct.GeneralSafeObjects;
import se.swedenconnect.sigval.pdf.pdfstruct.ObjectValue;
import se.swedenconnect.sigval.pdf.pdfstruct.ObjectValueType;
import se.swedenconnect.sigval.pdf.pdfstruct.PDFDocRevision;

@Slf4j
@NoArgsConstructor
public class DefaultGeneralSafeObjects implements GeneralSafeObjects {

  /** {@inheritDoc} */
  @Override
  public void addGeneralSafeObjects(final PDFDocRevision revData) {

    // TODO get safe objects
    final List<Long> safeObjects = revData.getSafeObjects();

    /*
     * First we will look into the root dictionary and locate a DSS, Metadata or Extensions object We will then add the
     * object ID to these objects as safe objects Further, we will add all objects inside the DSS object as safe
     * objects.
     */
    final COSBase baseObject = revData.getRootObject().getObject();
    if (baseObject instanceof COSDictionary) {
      final COSDictionary rootDic = (COSDictionary) baseObject;
      this.addSafeOjects(rootDic, safeObjects, Arrays.asList("DSS", "Extensions", "Metadata"));
      if (rootDic.containsKey("DSS")) {
        try {
          final COSObject dss = (COSObject) rootDic.getItem("DSS");
          final Dictionary dssDict = new Dictionary((COSDictionary) dss.getObject());
          dssDict.getValueMap().forEach((cosName, objectValue) -> {
            if (objectValue.getType().equals(ObjectValueType.COSObject)) {
              safeObjects.add((long) objectValue.getValue());
            }
          });
        }
        catch (final Exception ex) {
          log.debug("Error parsing DSS object in PDF revision");
        }
      }

      rootDic.entrySet().stream().forEach(cosNameCOSBaseEntry -> {
        cosNameCOSBaseEntry.getValue();
        cosNameCOSBaseEntry.getKey();
      });
    }

    // Finally, add the /Info object in the trailer as safe object
    try {
      final Dictionary trailer = new Dictionary(revData.getTrailer());
      final ObjectValue infoObj = trailer.getValueByName(COSName.INFO.getName());
      if (infoObj != null && infoObj.getType().equals(ObjectValueType.COSObject)) {
        safeObjects.add((long) infoObj.getValue());
      }
    }
    catch (final Exception ex) {
      log.debug("Error parsing INFO object in the PDF trailer");
    }
  }

  /**
   * Adds the object ID values of present objects to the list of safe objects
   *
   * @param rootDic
   *          the root dictionary
   * @param safeObjects
   *          the list of safe objects id:s to be amended
   * @param objNames
   *          the names of objects to be added to the list
   */
  private void addSafeOjects(final COSDictionary rootDic, final List<Long> safeObjects, final List<String> objNames) {
    objNames.stream()
      .filter(s -> rootDic.containsKey(s))
      .map(s -> new ObjectValue(rootDic.getItem(s)))
      .filter(objectValue -> objectValue.getType().equals(ObjectValueType.COSObject))
      .forEach(objectValue -> safeObjects.add((long) objectValue.getValue()));
  }
}
