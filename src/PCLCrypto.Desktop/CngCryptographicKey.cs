//-----------------------------------------------------------------------
// <copyright file="CngCryptographicKey.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;

    /// <summary>
    /// The .NET Framework implementation of the <see cref="ICryptographicKey"/> interface
    /// for CNG keys.
    /// </summary>
    internal class CngCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The platform crypto key.
        /// </summary>
        private readonly CngKey key;

        /// <summary>
        /// Initializes a new instance of the <see cref="CngCryptographicKey"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        internal CngCryptographicKey(CngKey key)
        {
            Requires.NotNull(key, "key");

            this.key = key;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.key.KeySize; }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            return this.key.Export(CngAsymmetricKeyAlgorithmProvider.GetPlatformKeyBlobType(blobType));
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            return this.key.Export(CngAsymmetricKeyAlgorithmProvider.GetPlatformKeyBlobType(blobType));
        }

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            throw new NotImplementedException();
        }
    }
}
