// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// A MAC algorithm provider.
    /// </summary>
    public interface IMacAlgorithmProvider
    {
        /// <summary>
        /// Gets the name of the open MAC algorithm.
        /// </summary>
        /// <value>
        /// The algorithm.
        /// </value>
        MacAlgorithm Algorithm { get; }

        /// <summary>
        /// Gets the length, in bytes, of the message authentication code.
        /// </summary>
        /// <value>
        /// Number of bytes in the MAC.
        /// </value>
        int MacLength { get; }

        /// <summary>
        /// Creates a CryptographicHash object that supports incremental hash operations.
        /// </summary>
        /// <param name="keyMaterial">Random data used to help generate the hash. You can call the GenerateRandom
        /// method to create the random data.</param>
        /// <returns>
        /// A CryptographicHash object that supports incremental hash operations.
        /// </returns>
        CryptographicHash CreateHash(byte[] keyMaterial);

        /// <summary>
        /// Creates a symmetric key that can be used to create the MAC value.
        /// </summary>
        /// <param name="keyMaterial">Random data used to help generate the key. You can call the GenerateRandom
        /// method to create the random data.</param>
        /// <returns>Symmetric key.</returns>
        ICryptographicKey CreateKey(byte[] keyMaterial);
    }
}
