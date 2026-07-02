/*
 * Copyright (c) 2026.  Sweden Connect
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
 *
 * This package contains classes for handling certificate extensions.
 *
 * Extensions are implemented as ASN.1 objects. This only implements the content of
 * extensions and does not handle whether the extension is critical or not.
 *
 * Criticality is handled when the extension is added to a certificate.
 */

package se.swedenconnect.cert.extensions;
