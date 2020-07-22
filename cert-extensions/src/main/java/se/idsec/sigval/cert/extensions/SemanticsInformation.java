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

package se.idsec.sigval.cert.extensions;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SemanticsInformation {
    ASN1ObjectIdentifier semanticsIdentifier;
    List<GeneralName> nameRegistrationAuthorityList;

    public SemanticsInformation(ASN1ObjectIdentifier semanticsIdentifier, List<GeneralName> nameRegistrationAuthorityList) {
        this.semanticsIdentifier = semanticsIdentifier;
        this.nameRegistrationAuthorityList = nameRegistrationAuthorityList;
    }

    public SemanticsInformation() {
    }

    public ASN1ObjectIdentifier getSemanticsIdentifier() {
        return semanticsIdentifier;
    }

    public void setSemanticsIdentifier(ASN1ObjectIdentifier semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
    }

    public List<GeneralName> getNameRegistrationAuthorityList() {
        if (nameRegistrationAuthorityList==null){
            return new ArrayList<>();
        }
        return nameRegistrationAuthorityList;
    }

    public void setNameRegistrationAuthorityList(List<GeneralName> nameRegistrationAuthorityList) {
        this.nameRegistrationAuthorityList = nameRegistrationAuthorityList;
    }
    
}
