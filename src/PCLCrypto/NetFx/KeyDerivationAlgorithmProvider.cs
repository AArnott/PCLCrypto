// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The .NET Framework implementation of the <see cref="IKeyDerivationAlgorithmProvider"/> interface.
    /// </summary>
    internal class KeyDerivationAlgorithmProvider : IKeyDerivationAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly KeyDerivationAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDerivationAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal KeyDerivationAlgorithmProvider(KeyDerivationAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public KeyDerivationAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public ICryptographicKey CreateKey(byte[] keyMaterial)
        {
            return new KeyDerivationCryptographicKey(this.Algorithm, keyMaterial);
        }
    }
}
