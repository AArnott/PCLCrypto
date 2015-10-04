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
        /// The symmetric algorithm used when creating this key, when applicable.
        /// </summary>
        private readonly SymmetricKeyAlgorithmProvider symmetricAlgorithmProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicKey" /> class.
        /// </summary>
        /// <param name="key">The WinRT cryptographic key.</param>
        internal CryptographicKey(Platform.CryptographicKey key)
        {
            Requires.NotNull(key, "key");

            this.key = key;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicKey" /> class.
        /// </summary>
        /// <param name="key">The WinRT cryptographic key.</param>
        /// <param name="symmetricAlgorithmProvider">The symmetric algorithm of the provider creating this key.</param>
        internal CryptographicKey(Platform.CryptographicKey key, SymmetricKeyAlgorithmProvider symmetricAlgorithmProvider)
        {
            Requires.NotNull(key, "key");

            this.key = key;
            this.symmetricAlgorithmProvider = symmetricAlgorithmProvider;
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

        /// <summary>
        /// Gets the symmetric algorithm provider that created this key, if applicable.
        /// </summary>
        internal SymmetricKeyAlgorithmProvider SymmetricAlgorithmProvider
        {
            get { return this.symmetricAlgorithmProvider; }
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
            catch (ArgumentException ex)
            {
                throw new InvalidOperationException(ex.Message, ex);
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

        /// <summary>
        /// Disposes of managed resources associated with this object.
        /// </summary>
        public void Dispose()
        {
        }
    }
}
