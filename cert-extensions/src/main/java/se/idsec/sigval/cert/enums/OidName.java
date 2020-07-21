/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.sigval.cert.enums;

import org.bouncycastle.asn1.x509.AccessDescription;

/**
 *
 * @author stefan
 */
public enum OidName {
    cp_anyPolicy("anyPolicy", "2.5.29.32.0"),
    cp_etsiQcPubSscd("ETSI QC Public with SSCD (0.4.0.1456.1.1)", "0.4.0.1456.1.1"),
    cp_etsiQcPub("ETSI QC Public (0.4.0.1456.1.2)", "0.4.0.1456.1.2"),
    cpsQualifier("CPS Qualifier", "1.3.6.1.5.5.7.2.1"),
    usernoticeQualifier("User notice Qualifier", "1.3.6.1.5.5.7.2.2"),
    serverAuth("Server Auth", "1.3.6.1.5.5.7.3.1"),
    clientAuth("Client Auth", "1.3.6.1.5.5.7.3.2"),
    codeSigning("Code Signing", "1.3.6.1.5.5.7.3.3"),
    emailProtection("Email Protection", "1.3.6.1.5.5.7.3.4"),
    timeStamping("Time Stamping", "1.3.6.1.5.5.7.3.8"),
    OCSPSigning("OCSP Signing", "1.3.6.1.5.5.7.3.9"),
    smartCardLogon("SmartCard Logon","1.3.6.1.4.1.311.20.2.2"),
    certRequestEnrollment("Cert Request Enrollment","1.3.6.1.4.1.311.20.2.1"),
    rootListSigning("Root List Signing","1.3.6.1.4.1.311.10.3.9"),
    etsiSemanticsID_Natural("id-etsi-qcs-semanticsId-Natural","0.4.0.194121.1.1"),
    etsiSemanticsID_Legal("id-etsi-qcs-semanticsId-Legal","0.4.0.194121.1.2"),
    eIDASSemanticsID_Natural("id-etsi-qcs-semanticsId-eIDASNatural","0.4.0.194121.1.3"),
    eIDASSemanticsID_Legal("id-etsi-qcs-semanticsId-eIDASLegal","0.4.0.194121.1.4"),
    entrVersionExt("Entrust Version Extension", "1.2.840.113533.7.65.0"),
    netscapeCertType("Netscape Certificate Type", "2.16.840.1.113730.1.1"),
    id_pkix_ad_caRepository("caRepository","1.3.6.1.5.5.7.48.5"),
    id_pkix_ad_timestamping("timeStamping","1.3.6.1.5.5.7.48.3"),
    id_pkix_ad_caIssuers("caIssuers", AccessDescription.id_ad_caIssuers.getId()),
    id_pkix_ad_ocsp("ocsp", AccessDescription.id_ad_ocsp.getId()),
    ;
    
    String name;
    String oid;

    private OidName(String name, String oid) {
        this.name = name;
        this.oid = oid;
    }

    public String getName() {
        return name;
    }

    public String getOid() {
        return oid;
    }
    
    
    
    public static String getName(String oidStr){
        for (OidName oid : values()){
            if (oid.getOid().equalsIgnoreCase(oidStr)){
                return oid.getName();
            }
        }
        return oidStr;
    }
    
}
