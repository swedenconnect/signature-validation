/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.swedenconnect.sigval.commons.algorithms;

import se.swedenconnect.sigval.commons.data.SigValIdentifiers;

/**
 * Enumeration of public key types
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public enum PublicKeyType {

    /** EC key */
    EC(SigValIdentifiers.ID_ECDSA),
    /** RSA key */
    RSA(SigValIdentifiers.ID_RSA),
    /** Unknown key type */
    Unknown(null);

    /** object identifier for the public algorithm associated with this key type */
    private String objectId;

    PublicKeyType(String objectId) {
        this.objectId = objectId;
    }

    /**
     * Getter for object ID parameter
     * @return the OID of the associated algorithm
     */
    public String getObjectId() {
        return objectId;
    }

    /**
     * Get the public key type for an algorithm OID
     * @param oid algorithm OID
     * @return Public key type
     */
    public static PublicKeyType getTypeFromOid(String oid){
        for (PublicKeyType pkType: values()){
            if (pkType.getObjectId().equalsIgnoreCase(oid)){
                return pkType;
            }
        }
        return Unknown;
    }
}
