/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.sigval.cert.extensions.missing;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import java.util.Date;

/**
 * The AuthorityInformationAccess object.
 * <pre>
 * id-pe-subjectInfoAccess OBJECT IDENTIFIER ::= { id-pe 11 }
 *
 * SubjectInfoAccessSyntax  ::=
 *      SEQUENCE SIZE (1..MAX) OF AccessDescription
 * AccessDescription  ::=  SEQUENCE {
 *       accessMethod          OBJECT IDENTIFIER,
 *       accessLocation        GeneralName  }
 *
 * </pre>
 */
public class PrivateKeyUsagePeriod
        extends ASN1Object {

    private Date notBefore;
    private Date notAfter;

    public static PrivateKeyUsagePeriod getInstance(
            Object obj) {
        if (obj instanceof PrivateKeyUsagePeriod) {
            return (PrivateKeyUsagePeriod) obj;
        }

        if (obj != null) {
            return new PrivateKeyUsagePeriod(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static PrivateKeyUsagePeriod fromExtensions(Extensions extensions) {
        return PrivateKeyUsagePeriod.getInstance(extensions.getExtensionParsedValue(Extension.authorityInfoAccess));
    }

    private PrivateKeyUsagePeriod(ASN1Sequence seq) {
        
        for (int i=0;i<seq.size();i++){
            try {
                ASN1TaggedObject taggedTime = ASN1TaggedObject.getInstance(seq.getObjectAt(i));
                ASN1Primitive taggedOject = taggedTime.getObject();
                ASN1GeneralizedTime time = ASN1GeneralizedTime.getInstance(taggedTime, false);
                int tagNo = taggedTime.getTagNo();
                if (tagNo==0){
                    notBefore = time.getDate();
                }
                if (tagNo==1){
                    notAfter = time.getDate();
                }
            } catch (Exception e) {
            }
        }        
    }


    public PrivateKeyUsagePeriod(Date notBefore, Date notAfter) {
        this.notBefore = notBefore;
        this.notAfter = notAfter;
    }

    public Date getNotBefore() {
        return notBefore;
    }

    public Date getNotAfter() {
        return notAfter;
    }


    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        
        if (notBefore!=null){
            DERGeneralizedTime nbTime = new DERGeneralizedTime(notBefore);
            DERTaggedObject nbTo = new DERTaggedObject(false, 0, nbTime);
            vec.add(nbTo);
        }
        if (notAfter!=null){
            DERGeneralizedTime naTime = new DERGeneralizedTime(notAfter);
            DERTaggedObject naTo = new DERTaggedObject(false, 1, naTime);
            vec.add(naTo);
        }
        return new DERSequence(vec);
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        if (notBefore!=null){
            b.append("NotBefore: ").append(notBefore).append("\n");
        }
        if (notAfter!=null){
            b.append("NotAfter: ").append(notAfter).append("\n");
        }
        return (b.toString());
    }
}
