//-----------------------------------------------------------------------
// <copyright file="CryptographicKey.cs" company="Andrew Arnott">
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
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// The WinRT implementation of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal class CryptographicKey : ICryptographicKey
    {
        /// <summary>
        /// The WinRT cryptographic key.
        /// </summary>
        private readonly Platform.CryptographicKey key;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicKey" /> class.
        /// </summary>
        /// <param name="key">The WinRT cryptographic key.</param>
        internal CryptographicKey(Platform.CryptographicKey key)
        {
            Requires.NotNull(key, "key");

            this.key = key;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return (int)this.key.KeySize; }
        }

        /// <summary>
        /// Gets the platform key.
        /// </summary>
        internal Platform.CryptographicKey Key
        {
            get { return this.key; }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            try
            {
                return this.key.Export(AsymmetricKeyAlgorithmProvider.GetPlatformKeyBlobType(blobType)).ToArray();
            }
            catch (NotImplementedException ex)
            {
                throw new NotSupportedException(ex.Message, ex);
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            try
            {
                return this.key.ExportPublicKey(AsymmetricKeyAlgorithmProvider.GetPlatformKeyBlobType(blobType)).ToArray();
            }
            catch (NotImplementedException ex)
            {
                throw new NotSupportedException(ex.Message, ex);
            }
        }
    }
}
