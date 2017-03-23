// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// A PCL-compatible enumeration describing symmetric cipher modes.
    /// </summary>
    public enum SymmetricAlgorithmMode
    {
        /// <summary>
        /// The algorithm is a streaming cipher rather than a block cipher.
        /// </summary>
        Streaming,

        /// <summary>
        /// The CBC mode.
        /// </summary>
        Cbc,

        /// <summary>
        /// The ECB mode.
        /// </summary>
        Ecb,

        /// <summary>
        /// Counter with CBC-MAC.
        /// It is an authenticated encryption algorithm designed to provide both authentication and confidentiality. CCM mode is only defined for block ciphers with a block length of 128 bits.
        /// </summary>
        Ccm,

        /// <summary>
        /// Galois/Counter Mode.
        /// An authenticated encryption algorithm designed to provide both data authenticity (integrity) and confidentiality. GCM is defined for block ciphers with a block size of 128 bits.
        /// </summary>
        Gcm,
    }
}
