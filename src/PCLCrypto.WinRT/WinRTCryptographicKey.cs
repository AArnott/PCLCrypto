// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// The WinRT implementation of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal class WinRTCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The WinRT cryptographic key.
        /// </summary>
        private readonly Platform.CryptographicKey key;

        /// <summary>
        /// A value indicating whether <see cref="Export(CryptographicPrivateKeyBlobType)"/>
        /// can be expected to work.
        /// </summary>
        private readonly bool canExportPrivateKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="WinRTCryptographicKey" /> class.
        /// </summary>
        /// <param name="key">The WinRT cryptographic key.</param>
        /// <param name="canExportPrivateKey">
        /// A value indicating whether <see cref="Export(CryptographicPrivateKeyBlobType)"/>
        /// can be expected to work.
        /// </param>
        internal WinRTCryptographicKey(Platform.CryptographicKey key, bool canExportPrivateKey)
        {
            Requires.NotNull(key, "key");

            this.key = key;
            this.canExportPrivateKey = canExportPrivateKey;
        }

        /// <inheritdoc />
        public int KeySize => (int)this.key.KeySize;

        /// <summary>
        /// Gets the platform key.
        /// </summary>
        internal Platform.CryptographicKey Key => this.key;

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
            catch (ArgumentException ex)
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

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            return Platform.CryptographicEngine.Sign(this.key, data.ToBuffer())
                .ToArray();
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            return Platform.CryptographicEngine.VerifySignature(
                this.key,
                data.ToBuffer(),
                signature.ToBuffer());
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            return Platform.CryptographicEngine.SignHashedData(this.key, data.ToBuffer())
                .ToArray();
        }

        /// <inheritdoc />
        protected internal override bool VerifyHash(byte[] data, byte[] signature)
        {
            return Platform.CryptographicEngine.VerifySignatureWithHashInput(
                this.key,
                data.ToBuffer(),
                signature.ToBuffer());
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] plaintext, byte[] iv)
        {
            try
            {
                return Platform.CryptographicEngine.Encrypt(this.Key, plaintext.ToBuffer(), iv.ToBuffer()).ToArray();
            }
            catch (NotImplementedException ex)
            {
                throw new NotSupportedException(ex.Message, ex);
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] ciphertext, byte[] iv)
        {
            return Platform.CryptographicEngine.Decrypt(this.Key, ciphertext.ToBuffer(), iv.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateEncryptor(byte[] iv)
        {
            return new BufferingCryptoTransform(input => this.Encrypt(input, iv));
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateDecryptor(byte[] iv)
        {
            return new BufferingCryptoTransform(input => this.Decrypt(input, iv));
        }

        /// <inheritdoc />
        protected internal override byte[] DeriveKeyMaterial(IKeyDerivationParameters parameters, int desiredKeySize)
        {
            var platformParameters = ((KeyDerivationParameters)parameters).Parameters;
            return Platform.CryptographicEngine.DeriveKeyMaterial(this.key, platformParameters, (uint)desiredKeySize).ToArray();
        }
    }
}
