// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Key derivation algorithms.
    /// </summary>
    public enum KeyDerivationAlgorithm
    {
        /// <summary>
        /// The Pbkdf2Md5 algorithm.
        /// </summary>
        Pbkdf2Md5,

        /// <summary>
        /// The Pbkdf2Sha1 algorithm.
        /// </summary>
        Pbkdf2Sha1,

        /// <summary>
        /// The Pbkdf2Sha256 algorithm.
        /// </summary>
        Pbkdf2Sha256,

        /// <summary>
        /// The Pbkdf2Sha384 algorithm.
        /// </summary>
        Pbkdf2Sha384,

        /// <summary>
        /// The Pbkdf2Sha512 algorithm.
        /// </summary>
        Pbkdf2Sha512,

        /// <summary>
        /// The Sp800108CtrHmacMd5 algorithm.
        /// </summary>
        Sp800108CtrHmacMd5,

        /// <summary>
        /// The Sp800108CtrHmacSha1 algorithm.
        /// </summary>
        Sp800108CtrHmacSha1,

        /// <summary>
        /// The Sp800108CtrHmacSha256 algorithm.
        /// </summary>
        Sp800108CtrHmacSha256,

        /// <summary>
        /// The Sp800108CtrHmacSha384 algorithm.
        /// </summary>
        Sp800108CtrHmacSha384,

        /// <summary>
        /// The Sp800108CtrHmacSha512 algorithm.
        /// </summary>
        Sp800108CtrHmacSha512,

        /// <summary>
        /// The Sp80056aConcatMd5 algorithm.
        /// </summary>
        Sp80056aConcatMd5,

        /// <summary>
        /// The Sp80056aConcatSha1 algorithm.
        /// </summary>
        Sp80056aConcatSha1,

        /// <summary>
        /// The Sp80056aConcatSha256 algorithm.
        /// </summary>
        Sp80056aConcatSha256,

        /// <summary>
        /// The Sp80056aConcatSha384 algorithm.
        /// </summary>
        Sp80056aConcatSha384,

        /// <summary>
        /// The Sp80056aConcatSha512 algorithm.
        /// </summary>
        Sp80056aConcatSha512,
    }
}
