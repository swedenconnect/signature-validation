/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.sigval.cert.extensions;

import java.math.BigInteger;

/**
 *
 * @author stefan
 */
public class MonetaryValue {
    String currency;
    BigInteger amount;
    BigInteger exponent;

    public MonetaryValue() {
    }

    public MonetaryValue(String currency, BigInteger amount, BigInteger exponent) {
        this.currency = currency;
        this.amount = amount;
        this.exponent = exponent;
    }

    public String getCurrency() {
        return currency;
    }

    public void setCurrency(String currency) {
        this.currency = currency;
    }

    public BigInteger getAmount() {
        return amount;
    }

    public void setAmount(BigInteger amount) {
        this.amount = amount;
    }

    public BigInteger getExponent() {
        return exponent;
    }

    public void setExponent(BigInteger exponent) {
        this.exponent = exponent;
    }

    
    
}
