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

package se.idsec.sigval.pdf.pdfstruct.impl;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.cos.*;
import se.idsec.sigval.pdf.pdfstruct.*;

import java.util.Arrays;
import java.util.List;

@Slf4j
@NoArgsConstructor
public class DefaultGeneralSafeObjects implements GeneralSafeObjects {

  /** {@inheritDoc} */
  @Override public void addGeneralSafeObjects(PDFDocRevision revData) {

    //TODO get safe objects
    List<Long> safeObjects = revData.getSafeObjects();

    /*
    First we will look into the root dictionary and locate a DSS, Metadata or Extensions object
    We will then add the object ID to these objects as safe objects
    Further, we will add all objects inside the DSS object as safe objects.
     */
    COSBase baseObject = revData.getRootObject().getObject();
    if (baseObject instanceof COSDictionary) {
      COSDictionary rootDic = (COSDictionary) baseObject;
      addSafeOjects(rootDic, safeObjects, Arrays.asList("DSS", "Extensions", "Metadata"));
      if (rootDic.containsKey("DSS")){
        try {
          COSObject dss = (COSObject)rootDic.getItem("DSS");
          Dictionary dssDict = new Dictionary((COSDictionary) dss.getObject());
          dssDict.getValueMap().forEach((cosName, objectValue) -> {
            if (objectValue.getType().equals(ObjectValueType.COSObject)){
              safeObjects.add((long)objectValue.getValue());
            }
          });
        } catch (Exception ex) {
          log.debug("Error parsing DSS object in PDF revision");
        }
      }

      rootDic.entrySet().stream().forEach(cosNameCOSBaseEntry -> {
        COSBase value = cosNameCOSBaseEntry.getValue();
        COSName key = cosNameCOSBaseEntry.getKey();
      });
    }

    // Finally, add the /Info object in the trailer as safe object
    try {
      Dictionary trailer = new Dictionary(revData.getTrailer());
      ObjectValue infoObj = trailer.getValueByName(COSName.INFO.getName());
      if (infoObj != null && infoObj.getType().equals(ObjectValueType.COSObject)) {
        safeObjects.add((long)infoObj.getValue());
      }
    } catch (Exception ex) {
      log.debug("Error parsing INFO object in the PDF trailer");
    }
  }

  /**
   * Adds the object ID values of present objects to the list of safe objects
   * @param rootDic the root dictionary
   * @param safeObjects the list of safe objects id:s to be amended
   * @param objNames the names of objects to be added to the list
   */
  private void addSafeOjects(COSDictionary rootDic, List<Long> safeObjects, List<String> objNames) {
    objNames.stream()
      .filter(s -> rootDic.containsKey(s))
      .map(s -> new ObjectValue(rootDic.getItem(s)))
      .filter(objectValue -> objectValue.getType().equals(ObjectValueType.COSObject))
      .forEach(objectValue -> safeObjects.add((long)objectValue.getValue()));
  }
}
