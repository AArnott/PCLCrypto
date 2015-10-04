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

        /// <summary>
        /// Disposes of managed resources associated with this object.
        /// </summary>
        public void Dispose()
        {
            // Delete the key since we may have created it with a name,
            // so that we can export it, but we do not wish for it to be
            // permanently recorded in the device's key store.
            this.key.Delete();
            this.key.Dispose();
        }
    }
}
