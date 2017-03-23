// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// The simple names of asymmetric algorithms.
    /// </summary>
    public enum AsymmetricAlgorithmName
    {
        /// <summary>
        /// Digital signing algorithm.
        /// </summary>
        Dsa,

        /// <summary>
        /// Elliptic curve digital signing algorithm.
        /// </summary>
        Ecdsa,

        /// <summary>
        /// RSA encryption.
        /// </summary>
        Rsa,

        /// <summary>
        /// RSA signature.
        /// </summary>
        RsaSign,
    }
}
