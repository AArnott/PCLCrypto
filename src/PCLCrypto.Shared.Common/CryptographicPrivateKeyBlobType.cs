// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Serialization formats for private keys.
    /// </summary>
    public enum CryptographicPrivateKeyBlobType
    {
        /// <summary>
        ///  The private key is encoded as an ASN.1 PrivateKeyInfo type defined in the PKCS#8 standard. The private key information syntax is defined as follows in RFC 5208.
        /// </summary>
        Pkcs8RawPrivateKeyInfo,

        /// <summary>
        /// The key is an RSA private key defined in the PKCS #1 standard. For more information, see the RSA Cryptography Specification in RFC 3447.
        /// </summary>
        Pkcs1RsaPrivateKey,

        /// <summary>
        /// Microsoft private key format defined by Cryptography API: Next Generation (CNG).
        /// </summary>
        BCryptPrivateKey,

        /// <summary>
        /// Microsoft full private key format defined by Cryptography API: Next Generation (CNG).
        /// </summary>
        BCryptFullPrivateKey,

        /// <summary>
        /// Microsoft private key format defined by the legacy Cryptography API (CAPI). For more information, see Base Provider Key BLOBs.
        /// </summary>
        Capi1PrivateKey,
    }
}
