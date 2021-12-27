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

package se.swedenconnect.cert.extensions.utils;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

public class ExtensionUtils {

  /** General name display names */
  private static final String[] generalNameTagText = new String[] {
    "Other Name",
    "E-Mail",
    "DNS",
    "x400Address",
    "Directory Name",
    "EDI Party Name",
    "URI",
    "IP Address",
    "Registered ID" };

  /**
   * Get the presentation name string of general names
   * @param genNames X.509 certificate general names
   * @return presentation string
   */
  @SuppressWarnings("unused")
  private static String getGeneralNamesString(GeneralNames genNames) {
    GeneralName[] names = genNames.getNames();
    StringBuilder b = new StringBuilder();
    b.append("GeneralNames {");
    for (int i = 0; i < names.length; i++) {
      b.append(getGeneralNameStr(names[i]));
      if (i + 1 < names.length) {
        b.append(" | ");
      }
    }
    b.append("}");
    return b.toString();
  }

  /**
   * Get the general name string for a particular general name
   * @param generalName general name
   * @return presentation string
   */
  public static String getGeneralNameStr(GeneralName generalName) {
    if (generalName == null) {
      return "null";
    }
    String toString = generalName.toString();
    try {
      int tagNo = Integer.valueOf(toString.substring(0, toString.indexOf(":")));
      return generalNameTagText[tagNo] + toString.substring(toString.indexOf(":"));

    }
    catch (Exception e) {
      return toString;
    }
  }

}
