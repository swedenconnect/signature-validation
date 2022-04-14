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
 * Type of proofs for POE (Proof of existence)
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
@AllArgsConstructor
public enum POETypeOfProof {
  VALIDATION("urn:etsi:019102:poetype:validation"),
  PROVIDED("urn:etsi:019102:poetype:provided"),
  POLICY("urn:etsi:019102:poetype:policy");

  /**
   * Main indication URI
   * @return The URI of the main indication
   */
  private String uri;

  /**
   * Get type of proof from URI
   * @param uri type of proof URI
   * @return {@link POETypeOfProof}
   * @throws IllegalArgumentException if no such URI exists
   */
  public static POETypeOfProof fromUri(String uri) {
    return Arrays.stream(values())
      .filter(poeTypeOfProof -> poeTypeOfProof.getUri().equalsIgnoreCase(uri))
      .findFirst()
      .orElseThrow(() -> new IllegalArgumentException("No such type of proof URI"));
  }
}
