// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

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
