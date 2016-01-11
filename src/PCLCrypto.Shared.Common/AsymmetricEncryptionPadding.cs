// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// A PCL-compatible enumeration describing asymmetric encryption padding options.
    /// </summary>
    public enum AsymmetricEncryptionPadding
    {
        /// <summary>
        /// No padding at all.
        /// </summary>
        None,

        /// <summary>
        /// The data will be padded with a random number to round out the block size.
        /// </summary>
        Pkcs1,

        /// <summary>
        /// Use Optimal Asymmetric Encryption Padding (OAEP).
        /// </summary>
        Oaep,
    }
}
