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

package se.idsec.sigval.pdf.pdfstruct;

import lombok.Getter;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Utility class for a PDF Dictionary used to compare and extract values from the Dictionary
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class Dictionary {
  Map<COSName, ObjectValue> valueMap;
  COSDictionary dictionary;

  /**
   * Constructor
   * @param dictionary the dictionary object holding the dictionary data
   */
  public Dictionary(COSDictionary dictionary) {
    this.dictionary = dictionary;
    valueMap = new HashMap<>();
    dictionary.entrySet().stream()
      .forEach(entry -> valueMap.put(entry.getKey(), new ObjectValue(entry.getValue())));
  }

  /**
   * Compare this dictionary with the values of another dictionary
   * @param matchDictionary the dictionary to match
   * @return true on match
   */
  public boolean matches(Object matchDictionary){
    if (!(matchDictionary instanceof Dictionary)) return false;
    Map<COSName, ObjectValue> matchDictionaryValueMap = ((Dictionary)matchDictionary).getValueMap();
    Set<COSName> cosNameSet = this.valueMap.keySet();
    if (cosNameSet.size() != matchDictionaryValueMap.keySet().size()){
      return false;
    }

    for (COSName key: cosNameSet){
      if (!valueMap.get(key).matches(matchDictionaryValueMap.get(key))){
        return false;
      }
    }
    return true;
  }

  /**
   * Gets the value of an item inside this dictionary
   * @param name the key used to locate the value
   * @return the value under the specified key
   */
  public ObjectValue getValueByName(String name) {
    // Check if a value by the target name is in the value map
    COSName cosName = COSName.getPDFName(name);
    if (valueMap.containsKey(cosName)){
      return valueMap.get(cosName);
    }

    // Check if a value by the target name is in one of the dictionaries in the value map
    Optional<ObjectValue> targetObjectOptional = valueMap.keySet().stream()
      .map(key -> valueMap.get(key))
      .filter(objectValue -> objectValue.getType().equals(ObjectValueType.COSDictionary))
      .map(objectValue -> ((Dictionary) objectValue.getValue()).getValueByName(name))
      .filter(objectValue -> objectValue != null)
      .findFirst();

    return targetObjectOptional.isPresent() ? targetObjectOptional.get() : null;
  }
}
