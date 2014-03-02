//-----------------------------------------------------------------------
// <copyright file="SymmetricCryptographicKey.cs" company="Andrew Arnott">
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
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET Framework implementation of <see cref="ICryptographicKey"/> for use with symmetric algorithms.
    /// </summary>
    internal class SymmetricCryptographicKey : CryptographicKey, ICryptographicKey, IDisposable
    {
        /// <summary>
        /// The platform's symmetric algorithm.
        /// </summary>
        private readonly Platform.SymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricCryptographicKey"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm, initialized with the key.</param>
        internal SymmetricCryptographicKey(Platform.SymmetricAlgorithm algorithm)
        {
            Requires.NotNull(algorithm, "algorithm");
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { throw new NotImplementedException(); }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public void Dispose()
        {
            var disposable = this.algorithm as IDisposable;
            if (disposable != null)
            {
                disposable.Dispose();
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[] iv)
        {
            if (iv == null)
            {
                iv = new byte[this.algorithm.BlockSize / 8];
            }

            var encryptor = this.algorithm.CreateEncryptor(this.algorithm.Key, iv);
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            if (iv == null)
            {
                iv = new byte[this.algorithm.BlockSize / 8];
            }

            var decryptor = this.algorithm.CreateDecryptor(this.algorithm.Key, iv);
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }
}
