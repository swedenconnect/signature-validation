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

package se.swedenconnect.cert.extensions.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import java.util.ArrayList;
import java.util.List;

/**
 * Semantics information data within a QCStatements extension
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
@NoArgsConstructor
public class SemanticsInformation {
    @Getter @Setter private ASN1ObjectIdentifier semanticsIdentifier;
    @Setter private List<GeneralName> nameRegistrationAuthorityList;

  /**
   * Gets the list of name registration authorities.
     * @return the list of name registration authorities or an empty list
     */
    public List<GeneralName> getNameRegistrationAuthorityList() {
        if (nameRegistrationAuthorityList==null){
            return new ArrayList<>();
        }
        return nameRegistrationAuthorityList;
    }
}
