//-----------------------------------------------------------------------
// <copyright file="IHashAlgorithmProvider.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Represents a cryptographic hash provider.
    /// </summary>
    public interface IHashAlgorithmProvider
    {
        /// <summary>
        /// Gets the algorithm this instance is configured to use.
        /// </summary>
        HashAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets the length, in bytes, of the hash.
        /// </summary>
        /// <value>
        /// Number of bytes in the hash.
        /// </value>
        int HashLength { get; }

        /// <summary>
        /// Creates a reusable ICryptographicHash object.
        /// </summary>
        /// <returns>Reusable hash object.</returns>
        CryptographicHash CreateHash();

        /// <summary>
        /// Hashes binary data.
        /// </summary>
        /// <param name="data">Data to be hashed.</param>
        /// <returns>Hashed data.</returns>
        byte[] HashData(byte[] data);
    }
}
