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

package se.swedenconnect.sigval.xml.svt;

/**
 * Enumeration class specifying identifiers for different XML SVT extension strategies
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public enum XMLDocumentSVTMethod {
  /** Replace any previous SVT in the XML signatures where a new SVT was successfully created */
  REPLACE,
  /** Append a new SVT to any existing SVT tokens */
  EXTEND;
}