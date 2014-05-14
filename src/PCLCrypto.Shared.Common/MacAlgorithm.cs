//-----------------------------------------------------------------------
// <copyright file="MacAlgorithm.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

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
