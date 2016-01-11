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
    using Windows.Security.Cryptography.Core;
    using Platform = Windows.Security.Cryptography;

    internal class WinRTCryptographicKey : CryptographicKey, ICryptographicKey
    {
        private readonly Platform.Core.CryptographicKey platformKey;

        internal WinRTCryptographicKey(Platform.Core.CryptographicKey platformKey)
        {
            Requires.NotNull(platformKey, nameof(platformKey));

            this.platformKey = platformKey;
        }

        /// <inheritdoc />
        public int KeySize => (int)this.platformKey.KeySize;

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            try
            {
                return this.platformKey.Export(blobType.ToPlatformKeyBlobType()).ToArray();
            }
            catch (NotImplementedException ex)
            {
                throw new NotSupportedException(ex.Message, ex);
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            return this.platformKey.ExportPublicKey(blobType.ToPlatformKeyBlobType()).ToArray();
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[] iv)
        {
            return Platform.Core.CryptographicEngine.Encrypt(this.platformKey, data.ToBuffer(), iv.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            return Platform.Core.CryptographicEngine.Decrypt(this.platformKey, data.ToBuffer(), iv.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            return Platform.Core.CryptographicEngine.Sign(this.platformKey, data.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            return Platform.Core.CryptographicEngine.VerifySignature(this.platformKey, data.ToBuffer(), signature.ToBuffer());
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            return Platform.Core.CryptographicEngine.SignHashedData(this.platformKey, data.ToBuffer()).ToArray();
        }

        /// <inheritdoc />
        protected internal override bool VerifyHash(byte[] data, byte[] signature)
        {
            return Platform.Core.CryptographicEngine.VerifySignatureWithHashInput(this.platformKey, data.ToBuffer(), signature.ToBuffer());
        }

        /// <inheritdoc />
        protected internal override byte[] DeriveKeyMaterial(IKeyDerivationParameters parameters, int desiredKeySize)
        {
            return Platform.Core.CryptographicEngine.DeriveKeyMaterial(
                this.platformKey,
                ((KeyDerivationParameters)parameters).Parameters,
                (uint)desiredKeySize).ToArray();
        }
    }
}
