//-----------------------------------------------------------------------
// <copyright file="CryptographicPublicKeyBlobType.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

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
        X509SubjectPublicKeyInfo,
        Pkcs1RsaPublicKey,
        BCryptPublicKey,
        Capi1PublicKey,
    }
}
