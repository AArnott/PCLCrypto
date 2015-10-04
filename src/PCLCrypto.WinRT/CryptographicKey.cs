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
        /// A value indicating whether <see cref="Export(CryptographicPrivateKeyBlobType)"/>
        /// can be expected to work.
        /// </summary>
        private readonly bool canExportPrivateKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicKey" /> class.
        /// </summary>
        /// <param name="key">The WinRT cryptographic key.</param>
        /// <param name="canExportPrivateKey">
        /// A value indicating whether <see cref="Export(CryptographicPrivateKeyBlobType)"/>
        /// can be expected to work.
        /// </param>
        internal CryptographicKey(Platform.CryptographicKey key, bool canExportPrivateKey)
        {
            Requires.NotNull(key, "key");

            this.key = key;
            this.canExportPrivateKey = canExportPrivateKey;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptographicKey" /> class.
        /// </summary>
        /// <param name="key">The WinRT cryptographic key.</param>
        /// <param name="symmetricAlgorithmProvider">The symmetric algorithm of the provider creating this key.</param>
        /// <param name="canExportPrivateKey">
        /// A value indicating whether <see cref="Export(CryptographicPrivateKeyBlobType)"/>
        /// can be expected to work.
        /// </param>
        internal CryptographicKey(Platform.CryptographicKey key, SymmetricKeyAlgorithmProvider symmetricAlgorithmProvider, bool canExportPrivateKey)
            : this(key, canExportPrivateKey)
        {
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
                // ArgumentException can be thrown when we don't have the private key,
                // or when the key can't be serialized using the requested format.
                // The first of these deserves an InvalidOperationException while
                // the second one deserves a NotSupportedException. But we can't clearly
                // discern each case from the exception. So we use internal state to assist.
                if (this.canExportPrivateKey)
                {
                    // Exporting should work, so it must be an unsupported format.
                    throw new NotSupportedException(ex.Message, ex);
                }
                else
                {
                    // We can't have been expected to export regardless of the setting.
                    throw new InvalidOperationException(ex.Message, ex);
                }
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
