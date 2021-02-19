/*
 * Copyright (c) 2021. IDsec Solutions AB
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

package se.idsec.sigval.cert.chain.impl;

import se.idsec.sigval.cert.validity.CertificateValidityChecker;
import se.idsec.sigval.cert.validity.crl.CRLCache;

import java.beans.PropertyChangeListener;
import java.security.cert.X509Certificate;

public interface CertificateValidityCheckerFactory {

  CertificateValidityChecker getCertificateValidityChecker(X509Certificate certificate, X509Certificate issuer, CRLCache crlCache, PropertyChangeListener... propertyChangeListeners);
}
