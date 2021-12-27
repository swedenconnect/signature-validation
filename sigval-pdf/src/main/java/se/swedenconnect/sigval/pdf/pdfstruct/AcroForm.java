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

import lombok.Getter;
import org.apache.pdfbox.cos.*;

import java.io.IOException;

/**
 * Utility class for an AcroForm used to compare and extract values from the AcroForm
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AcroForm {
  @Getter private Dictionary dictionary;

  /**
   * Constructor
   *
   * @param objectValue the object holding the AcroForm data or reference to AcroForm data
   * @param cosDocument the {@link COSDocument} holding information about the document containing the AcroForm
   */
  public AcroForm(COSBase objectValue, COSDocument cosDocument) {
    ObjectValue value = new ObjectValue(objectValue);
    if (value.getType().equals(ObjectValueType.COSDictionary)) {
      dictionary = (Dictionary) value.getValue();
      return;
    }
    if (value.getType().equals(ObjectValueType.COSObject)) {
      try {
        COSObject refObject = cosDocument.getObjectFromPool(new COSObjectKey((COSObject) objectValue));
        dictionary = new Dictionary((COSDictionary) refObject.getObject());
      }
      catch (IOException e) {
        e.printStackTrace();
      }
    }
  }

  /**
   * Math the content with this Acroform with another AcroForm
   * @param matchForm the AcroForm to match agains
   * @return true on match
   */
  public boolean matches (AcroForm matchForm) {
    if (dictionary == null || matchForm.getDictionary() == null) return false;
    return dictionary.matches(matchForm.getDictionary());
  }

  /**
   * Get the object identifier value referenced by an inner dictionary inside the AcroForm
   * <p>Example: if the path "DS" and "Font" is provided, this function looks for a dictionary under key "DS"
   * containing an object under the key "Font"</p>
   *
   * @param path the COSName identifying sub dictionaries and finally the key
   *             of the target object inside the AcroFrom
   * @return the object identifier value of the target
   */
  public long getObjectRef(String... path){
    if (path == null || path.length ==0) return -1;

    Dictionary searchDictionary = dictionary;
    ObjectValue lastValue = null;
    for (String name : path){
      if (searchDictionary == null) return -1;
      lastValue = searchDictionary.getValueByName(name);
      if (lastValue == null) return -1;
      if (lastValue.getType().equals(ObjectValueType.COSDictionary)){
        searchDictionary = (Dictionary)lastValue.getValue();
      }
    }
    if (lastValue.getType().equals(ObjectValueType.COSObject)){
      return (long) lastValue.getValue();
    }
    return -1;
  }

}
