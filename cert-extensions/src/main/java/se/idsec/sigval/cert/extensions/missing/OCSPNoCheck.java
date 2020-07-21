/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.sigval.cert.extensions.missing;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;

public class OCSPNoCheck extends ASN1Object {

    public static final ASN1ObjectIdentifier OID = OCSPObjectIdentifiers.id_pkix_ocsp_nocheck;


    public static OCSPNoCheck getInstance() {
            return new OCSPNoCheck();
    }


    public OCSPNoCheck() {
    }


    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * InhibitAnyPolicy ::= SkipCerts
     * 
     * SkipCerts ::= INTEGER (0..MAX)
     * </pre>
     *
     * @return
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        return DERNull.INSTANCE;
    }

    @Override
    public String toString() {
        return "OCSP Nocheck";
    }
}
