/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.sigval.cert.extensions.missing;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import se.idsec.sigval.cert.enums.OidName;

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
public class SubjectInformationAccess extends ASN1Object {

    public static final ASN1ObjectIdentifier caRepository = new ASN1ObjectIdentifier(OidName.id_pkix_ad_caRepository.getOid());
    public static final ASN1ObjectIdentifier timeStamping = new ASN1ObjectIdentifier(OidName.id_pkix_ad_timestamping.getOid());
    private AccessDescription[] descriptions;

    public static SubjectInformationAccess getInstance(
            Object obj) {
        if (obj instanceof SubjectInformationAccess) {
            return (SubjectInformationAccess) obj;
        }

        if (obj != null) {
            return new SubjectInformationAccess(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static SubjectInformationAccess fromExtensions(Extensions extensions) {
        return SubjectInformationAccess.getInstance(extensions.getExtensionParsedValue(Extension.authorityInfoAccess));
    }

    private SubjectInformationAccess(
            ASN1Sequence seq) {
        if (seq.size() < 1) {
            throw new IllegalArgumentException("sequence may not be empty");
        }

        descriptions = new AccessDescription[seq.size()];

        for (int i = 0; i != seq.size(); i++) {
            descriptions[i] = AccessDescription.getInstance(seq.getObjectAt(i));
        }
    }

    public SubjectInformationAccess(
            AccessDescription description) {
        this(new AccessDescription[]{description});
    }

    public SubjectInformationAccess(
            AccessDescription[] descriptions) {
        this.descriptions = new AccessDescription[descriptions.length];
        System.arraycopy(descriptions, 0, this.descriptions, 0, descriptions.length);
    }

    /**
     * create an AuthorityInformationAccess with the oid and location provided.
     */
    public SubjectInformationAccess(
            ASN1ObjectIdentifier oid,
            GeneralName location) {
        this(new AccessDescription(oid, location));
    }

    /**
     *
     * @return the access descriptions contained in this object.
     */
    public AccessDescription[] getAccessDescriptions() {
        return descriptions;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector();

        for (int i = 0; i != descriptions.length; i++) {
            vec.add(descriptions[i]);
        }

        return new DERSequence(vec);
    }

    public String toString() {
        return ("SubjectInformationAccess: Oid(" + this.descriptions[0].getAccessMethod().getId() + ")");
    }
}
