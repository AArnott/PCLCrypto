// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// A PCL-compatible enumeration describing cipher block padding options.
    /// </summary>
    public enum SymmetricAlgorithmPadding
    {
        /// <summary>
        /// Use no padding at all.
        /// </summary>
        None,

        /// <summary>
        /// The PKCS #7 padding string consists of a sequence of bytes, each of which is equal to the total number of padding bytes added.
        /// </summary>
        PKCS7,

        /// <summary>
        /// The padding string consists of bytes set to zero.
        /// </summary>
        Zeros,
    }
}
