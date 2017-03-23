// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Provides key derivation functions.
    /// </summary>
    public interface IKeyDerivationAlgorithmProvider
    {
        /// <summary>
        /// Gets the algorithm used by this instance.
        /// </summary>
        KeyDerivationAlgorithm Algorithm { get; }

        /// <summary>
        /// Returns a key that may be used to derive another key.
        /// </summary>
        /// <param name="keyMaterial">The key material to use for the cryptographic key.</param>
        /// <returns>A cryptographic key.</returns>
        ICryptographicKey CreateKey(byte[] keyMaterial);
    }
}
