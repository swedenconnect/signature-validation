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
import org.apache.pdfbox.cos.*;

/**
 * PDF object value class used to store and compare object values. Object values stored in this class are not exhaustive.
 * They are limited to values relevant for the function of {@link PDFSignatureContext} implementations.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
public class ObjectValue {

  /** The type of the object value */
  private ObjectValueType type;
  /** The value of the object */
  private Object value;

  /**
   * Constructor
   * @param objectValue the value being stored and compared
   */
  public ObjectValue(COSBase objectValue) {
    if (objectValue == null){
      type = ObjectValueType.Null;
      value = null;
      return;
    }
    if (objectValue instanceof COSString){
      type = ObjectValueType.COSString;
    }
    if (objectValue instanceof COSArray){
      type = ObjectValueType.COSArray;
    }
    if (objectValue instanceof COSObject){
      type = ObjectValueType.COSObject;
    }
    if (objectValue instanceof COSName){
      type = ObjectValueType.COSName;
    }
    if (objectValue instanceof COSBoolean){
      type = ObjectValueType.COSBoolean;
    }
    if (objectValue instanceof COSInteger){
      type = ObjectValueType.COSInteger;
    }
    if (objectValue instanceof COSDictionary){
      type = ObjectValueType.COSDictionary;
    }
    if (objectValue instanceof COSNumber){
      type = ObjectValueType.COSNumber;
    }
    // Set type to other if we didn't detect type above
    type = type == null ? ObjectValueType.Other : type;
    getObjectValue(objectValue);
  }

  /**
   * Compare values
   * @param matchValue the value to compare with
   * @return true on match
   */
  public boolean matches(ObjectValue matchValue){
    if (matchValue == null) return false;
    // Require types to match
    if (!type.equals(matchValue.getType())) return false;
    Object matchValueValue = matchValue.getValue();

    switch (type) {
    case COSInteger:
    case COSNumber:
    case COSObject:
      return (long) value == (long) matchValueValue;
    case COSDictionary:
      return ((Dictionary) this.value).matches(matchValueValue);
    case COSName:
    case COSString:
      return ((String)value).equalsIgnoreCase((String)matchValueValue);
    case COSArray:
      return ((ObjectArray) this.value).matches(matchValueValue);
    case Other:
      return true;
    case Error:
    case Null:
      return false;
    case COSBoolean:
      return Boolean.compare((boolean)value, (boolean)matchValueValue) == 0;
    }
    return false;
  }

  /**
   * Extracts the value form a {@link COSBase} object
   * @param objectValue object value source
   */
  private void getObjectValue(COSBase objectValue) {
    try {
      
      switch (type) {
      case COSObject:
        value = ((COSObject)objectValue).getObjectNumber();
        break;
      case COSDictionary:
        value = new Dictionary((COSDictionary)objectValue);
        break;
      case COSName:
        value = ((COSName)objectValue).getName();
        break;
      case COSString:
        value = ((COSString)objectValue).getString();
        break;
      case COSArray:
        value = new ObjectArray((COSArray)objectValue);
        break;
      case Other:
        value = null;
        break;
      case COSBoolean:
        value = ((COSBoolean)objectValue).getValue();
        break;
      case COSInteger:
        value = ((COSInteger)objectValue).longValue();
        break;
      case COSNumber:
        value = ((COSNumber)objectValue).longValue();
        break;
      default:
        type = ObjectValueType.Error;
        value = null;
        break;
      }
    } 
    catch (Exception ex) {
      type = ObjectValueType.Error;
      value = null;
    }
  }
}
