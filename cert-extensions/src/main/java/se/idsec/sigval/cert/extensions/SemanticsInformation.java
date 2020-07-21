/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.sigval.cert.extensions;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author stefan
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
