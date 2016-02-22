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
    using Platform = System.Security.Cryptography;

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

        /// <inheritdoc />
        protected internal override byte[] DeriveKeyMaterial(IKeyDerivationParameters parameters, int desiredKeySize)
        {
            // Right now we're assuming that KdfGenericBinary is directly usable as a salt
            // in RFC2898. When our KeyDerivationParametersFactory class supports
            // more parameter types than just BuildForPbkdf2, we might need to adjust this code
            // to handle each type of parameter.
            byte[] salt = parameters.KdfGenericBinary;
            switch (this.Algorithm)
            {
                case KeyDerivationAlgorithm.Pbkdf2Sha1:
                    var deriveBytes = new Platform.Rfc2898DeriveBytes(this.Key, salt, parameters.IterationCount);
                    return deriveBytes.GetBytes(desiredKeySize);
                default:
                    // TODO: consider using Platform.PasswordDeriveBytes if it can
                    // support some more of these algorithms.
                    throw new NotSupportedException("Only KeyDerivationAlgorithm.Pbkdf2Sha1 is supported for this platform.");
            }
        }
    }
}
