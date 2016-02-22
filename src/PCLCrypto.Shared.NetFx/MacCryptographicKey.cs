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

    /// <summary>
    /// A .NET Framework implementation of the <see cref="ICryptographicKey"/> interface
    /// for use with MACs.
    /// </summary>
    internal class MacCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The algorithm to use when hashing.
        /// </summary>
        private readonly MacAlgorithm algorithm;

        /// <summary>
        /// The key material.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// Initializes a new instance of the <see cref="MacCryptographicKey" /> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="key">The key.</param>
        internal MacCryptographicKey(MacAlgorithm algorithm, byte[] key)
        {
            Requires.NotNull(key, "key");
            this.algorithm = algorithm;
            this.key = key;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.key.Length; }
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
        protected internal override byte[] Sign(byte[] data)
        {
            using (var algorithm = MacAlgorithmProvider.GetAlgorithm(this.algorithm))
            {
#if Android
                algorithm.Init(MacAlgorithmProvider.GetSecretKey(this.algorithm, this.key));
                return algorithm.DoFinal(data);
#else
                algorithm.Key = this.key;
                return algorithm.ComputeHash(data);
#endif
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            using (var algorithm = MacAlgorithmProvider.GetAlgorithm(this.algorithm))
            {
                byte[] computedMac;
#if Android
                algorithm.Init(MacAlgorithmProvider.GetSecretKey(this.algorithm, this.key));
                computedMac = algorithm.DoFinal(data);
#else
                algorithm.Key = this.key;
                computedMac = algorithm.ComputeHash(data);
#endif
                return CryptoUtilities.BufferEquals(computedMac, signature);
            }
        }
    }
}
