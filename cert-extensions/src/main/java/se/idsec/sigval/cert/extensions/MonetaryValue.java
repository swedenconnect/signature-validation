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

import java.math.BigInteger;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
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
