// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    /// <summary>
    /// MAC algorithms available on the various platforms.
    /// </summary>
    public enum MacAlgorithm
    {
        /// <summary>
        /// The AesCmac algorithm.
        /// </summary>
        AesCmac,

        /// <summary>
        /// The HmacMd5 algorithm.
        /// </summary>
        HmacMd5,

        /// <summary>
        /// The HmacSha1 algorithm.
        /// </summary>
        HmacSha1,

        /// <summary>
        /// The HmacSha256 algorithm.
        /// </summary>
        HmacSha256,

        /// <summary>
        /// The HmacSha384 algorithm.
        /// </summary>
        HmacSha384,

        /// <summary>
        /// The HmacSha512 algorithm.
        /// </summary>
        HmacSha512,
    }
}
