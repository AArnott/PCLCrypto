// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

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
        /// The ECC Private key blob from which this key was imported, if applicable.
        /// </summary>
        private readonly byte[] eccPrivateKeyBlob;

        /// <summary>
        /// Initializes a new instance of the <see cref="CngCryptographicKey"/> class.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="eccPrivateKeyBlob">The ECC Private key blob from which this key was imported, if applicable.</param>
        internal CngCryptographicKey(CngKey key, byte[] eccPrivateKeyBlob)
        {
            Requires.NotNull(key, "key");

            this.key = key;
            this.eccPrivateKeyBlob = eccPrivateKeyBlob.CloneArray();
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.key.KeySize; }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            try
            {
                if (blobType == CryptographicPrivateKeyBlobType.BCryptPrivateKey && this.eccPrivateKeyBlob != null)
                {
                    // Imported keys are always ephemeral and cannot be exported.
                    // But we can make the API work if we have the private key data.
                    // Copy the key data before returning it to avoid sharing an array
                    // with the caller that would allow the caller to change our key data.
                    return this.eccPrivateKeyBlob.CloneArray();
                }

                return this.key.Export(CngAsymmetricKeyAlgorithmProvider.GetPlatformKeyBlobType(blobType));
            }
            catch (CryptographicException ex)
            {
                if (ex.IsNotSupportedException())
                {
                    throw new NotSupportedException(ex.Message, ex);
                }

                throw;
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            return this.key.Export(CngAsymmetricKeyAlgorithmProvider.GetPlatformKeyBlobType(blobType));
        }

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            using (var cng = new ECDsaCng(this.key))
            {
                return cng.SignData(data);
            }
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            using (var cng = new ECDsaCng(this.key))
            {
                return cng.SignHash(data);
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            using (var cng = new ECDsaCng(this.key))
            {
                return cng.VerifyData(data, signature);
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifyHash(byte[] data, byte[] signature)
        {
            using (var cng = new ECDsaCng(this.key))
            {
                return cng.VerifyHash(data, signature);
            }
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Delete the key since we may have created it with a name,
                // so that we can export it, but we do not wish for it to be
                // permanently recorded in the device's key store.
                this.key.Delete();
                this.key.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}
