/*
 * Copyright (c) 2020-2022. Sweden Connect
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
package se.swedenconnect.sigval.jose.data;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.UnprotectedHeader;

import lombok.Getter;
import lombok.Setter;
import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;

/**
 * Extended signature validation result for JSON signatures.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedJOSESigvalResult extends ExtendedSigValResult {

  /** Signature value of the JOSE signature. */
  @Getter
  @Setter
  private byte[] signatureValue;

  /** The JWS header of the signature. */
  @Getter
  @Setter
  private JWSHeader header;

  /** The unprotected header of the signature if present. */
  @Getter
  @Setter
  private UnprotectedHeader unprotectedHeader;

  /** The payload of the signature (embedded or detached). */
  @Getter
  @Setter
  private Payload payload;

}
