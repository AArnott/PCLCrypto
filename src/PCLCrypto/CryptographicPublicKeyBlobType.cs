// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Serialization formats for public keys.
    /// </summary>
    public enum CryptographicPublicKeyBlobType
    {
        /// <summary>
        /// The public key is encoded as an ASN.1 SubjectPublicKeyInfo type defined in RFC 5280 and RFC 3280.
        /// </summary>
        X509SubjectPublicKeyInfo,

        /// <summary>
        /// The key is an RSA public key defined in the PKCS #1 standard. For more information, see the RSA Cryptography Specification in RFC 3447.
        /// </summary>
        Pkcs1RsaPublicKey,

        /// <summary>
        /// Microsoft public key format defined by Cryptography API: Next Generation (CNG).
        /// </summary>
        BCryptPublicKey,

        /// <summary>
        /// Microsoft public key format defined by the legacy Cryptography API (CAPI).
        /// </summary>
        Capi1PublicKey,
    }
}
