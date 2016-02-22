// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Represents a provider of symmetric key algorithms.
    /// </summary>
    public interface ISymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// Gets the size, in bytes, of the cipher block for the open algorithm.
        /// </summary>
        /// <value>Block size.</value>
        int BlockLength { get; }

        /// <summary>
        /// Gets the allowed key sizes.
        /// </summary>
        IReadOnlyList<KeySizes> LegalKeySizes { get; }

        /// <summary>
        /// Gets the algorithm used in this algorithm.
        /// </summary>
        SymmetricAlgorithmName Name { get; }

        /// <summary>
        /// Gets the mode used in this algorithm.
        /// </summary>
        SymmetricAlgorithmMode Mode { get; }

        /// <summary>
        /// Gets the padding used in this algorithm.
        /// </summary>
        SymmetricAlgorithmPadding Padding { get; }

        /// <summary>
        /// Creates a symmetric key.
        /// </summary>
        /// <param name="keyMaterial">
        /// Data used to generate the key. You can call the GenerateRandom method to
        /// create random key material.
        /// </param>
        /// <returns>Symmetric key.</returns>
        ICryptographicKey CreateSymmetricKey(byte[] keyMaterial);
    }
}
