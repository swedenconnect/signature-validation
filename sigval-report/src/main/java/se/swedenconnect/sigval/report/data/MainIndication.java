/*
 * Copyright (c) 2022. IDsec Solutions AB
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

package se.swedenconnect.sigval.report.data;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.Arrays;

/**
 * Enumerations of signature validation result main indications according to EN 119 102-2 version 1.3.1
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
@AllArgsConstructor
public enum MainIndication {
  /** For signature validation indication */
  TOTAL_PASSED("urn:etsi:019102:mainindication:total-passed"),
  /** For signature validation indication */
  TOTAL_FAILED("urn:etsi:019102:mainindication:total-failed"),
  /** For any indeterminate result indication */
  INDETERMINATE("urn:etsi:019102:mainindication:indeterminate"),
  /** For individual validation constraint report or signature validation object validation */
  PASSED("urn:etsi:019102:mainindication:passed"),
  /** For individual validation constraint report or signature validation object validation */
  FAILED("urn:etsi:019102:mainindication:failed");

  /**
   * Main indication URI
   * @return The URI of the main indication
   */
  private String uri;

  /**
   * Get Main Indication from URI
   * @param uri main indication URI
   * @return {@link MainIndication}
   * @throws IllegalArgumentException if no such URI exists
   */
  public static MainIndication fromUri(String uri) {
    return Arrays.stream(values())
      .filter(mainIndication -> mainIndication.getUri().equalsIgnoreCase(uri))
      .findFirst()
      .orElseThrow(() -> new IllegalArgumentException("No such main indication URI"));
  }

}
