//-----------------------------------------------------------------------
// <copyright file="RsaCryptographicKey.cs" company="Andrew Arnott">
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
    /// for RSA keys.
    /// </summary>
    internal class RsaCryptographicKey : ICryptographicKey
    {
        /// <summary>
        /// The platform crypto key.
        /// </summary>
        private readonly RSACryptoServiceProvider key;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey"/> class.
        /// </summary>
        /// <param name="key">The RSA crypto service provider.</param>
        internal RsaCryptographicKey(RSACryptoServiceProvider key)
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
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo:
                    return this.key.ExportCspBlob(includePrivateParameters: true);
                default:
                    throw new NotSupportedException();
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                    return this.key.ExportCspBlob(includePrivateParameters: false);
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
