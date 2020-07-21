/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.sigval.cert.extensions.missing;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.X509Extension;

import java.math.BigInteger;

public class InhibitAnyPolicy extends ASN1Object {

    public static final ASN1ObjectIdentifier OID = Extension.inhibitAnyPolicy;
    BigInteger skipCerts;

    public static InhibitAnyPolicy getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Integer.getInstance(obj, explicit));
    }

    public static InhibitAnyPolicy getInstance(Object obj) {
        if (obj instanceof InhibitAnyPolicy) {
            return (InhibitAnyPolicy) obj;
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        if (obj != null) {
            return new InhibitAnyPolicy(ASN1Integer.getInstance(obj));
        }

        return null;
    }

    public static InhibitAnyPolicy fromExtensions(Extensions extensions) {
        return InhibitAnyPolicy.getInstance(extensions.getExtensionParsedValue(OID));
    }

    /**
     * Parse the content of ASN1 sequence to populate set values
     *
     * @param seq
     */
    private InhibitAnyPolicy(ASN1Integer skipCerts) {
        try {
            this.skipCerts = skipCerts.getPositiveValue();
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad extension content");
        }
    }

    public InhibitAnyPolicy(int skipcerts) {
        this.skipCerts = BigInteger.valueOf(skipcerts);
    }

    public BigInteger getSkipCerts() {
        return skipCerts;
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
        return new ASN1Integer(skipCerts);
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append("Skip certs: ").append(skipCerts).append("\n");
        return b.toString();
    }
}
