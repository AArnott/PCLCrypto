//-----------------------------------------------------------------------
// <copyright file="KeyDerivationCryptographicKey.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

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
        /// The key material.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDerivationCryptographicKey"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        internal KeyDerivationCryptographicKey(byte[] key)
        {
            Requires.NotNull(key, "key");
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
    }
}
