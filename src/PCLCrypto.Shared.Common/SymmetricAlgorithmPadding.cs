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
        /// Use PKCS7 padding.
        /// </summary>
        PKCS7,
    }
}
