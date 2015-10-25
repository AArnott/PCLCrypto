// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;

    /// <summary>
    /// A .NET Framework implementation of the <see cref="ICryptographicKey"/> interface
    /// for use with <see cref="KeyDerivationAlgorithmProvider"/>.
    /// </summary>
    internal class KeyDerivationCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The algorithm to use when deriving a cryptographic key.
        /// </summary>
        private readonly KeyDerivationAlgorithm algorithm;

        /// <summary>
        /// The key material.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDerivationCryptographicKey"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm to use when deriving a cryptographic key.</param>
        /// <param name="key">The key.</param>
        internal KeyDerivationCryptographicKey(KeyDerivationAlgorithm algorithm, byte[] key)
        {
            Requires.NotNull(key, "key");
            this.algorithm = algorithm;
            this.key = key;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.key.Length * 8; }
        }

        /// <summary>
        /// Gets the key material.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        internal byte[] Key
        {
            get { return this.key; }
        }

        /// <summary>
        /// Gets the algorithm to use when deriving a cryptographic key.
        /// </summary>
        internal KeyDerivationAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Disposes of managed resources associated with this object.
        /// </summary>
        public void Dispose()
        {
        }
    }
}
