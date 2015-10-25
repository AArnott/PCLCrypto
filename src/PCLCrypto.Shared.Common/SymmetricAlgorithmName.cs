// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// A PCL-compatible enumeration describing symmetric algorithms.
    /// </summary>
    public enum SymmetricAlgorithmName
    {
        /// <summary>
        /// The AES algorithm.
        /// </summary>
        Aes,

        /// <summary>
        /// The DES algorithm.
        /// </summary>
        Des,

        /// <summary>
        /// The TRIPLEDES algorithm.
        /// </summary>
        TripleDes,

        /// <summary>
        /// The RC2 algorithm.
        /// </summary>
        Rc2,

        /// <summary>
        /// The RC4 algorithm.
        /// </summary>
        Rc4,
    }
}
