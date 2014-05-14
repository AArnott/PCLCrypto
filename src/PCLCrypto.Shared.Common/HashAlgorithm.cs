//-----------------------------------------------------------------------
// <copyright file="HashAlgorithm.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    /// <summary>
    /// Hash algorithms.
    /// </summary>
    public enum HashAlgorithm
    {
        /// <summary>
        /// The MD5 algorithm.
        /// </summary>
        Md5,

        /// <summary>
        /// The SHA1 algorithm.
        /// </summary>
        Sha1,

        /// <summary>
        /// The SHA256 algorithm.
        /// </summary>
        Sha256,

        /// <summary>
        /// The SHA384 algorithm.
        /// </summary>
        Sha384,

        /// <summary>
        /// The SHA512 algorithm.
        /// </summary>
        Sha512,
    }
}
