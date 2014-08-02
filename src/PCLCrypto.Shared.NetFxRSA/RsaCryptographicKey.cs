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
    using PCLCrypto.Formatters;
    using Validation;

    /// <summary>
    /// The .NET Framework implementation of the <see cref="ICryptographicKey"/> interface
    /// for RSA keys.
    /// </summary>
    internal class RsaCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The platform crypto key.
        /// </summary>
        private readonly RSA key;

        /// <summary>
        /// The algorithm to use when performing cryptography.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="key">The RSA crypto service provider.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(RSA key, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(key, "key");

            this.key = key;
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.key.KeySize; }
        }

        /// <summary>
        /// Gets the RSA crypto service provider that contains this key.
        /// </summary>
        internal RSA Rsa
        {
            get { return this.key; }
        }

        /// <summary>
        /// Gets the algorithm to use with this key.
        /// </summary>
        internal AsymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            try
            {
                return KeyFormatter.GetFormatter(blobType).Write(KeyFormatter.ToPCLParameters(this.key.ExportParameters(true)));
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException("Private key not available.", ex);
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            return KeyFormatter.GetFormatter(blobType).Write(KeyFormatter.ToPCLParameters(this.key.ExportParameters(false)));
        }

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            using (var hash = CryptographicEngine.GetHashAlgorithm(this.Algorithm))
            {
                var formatter = new RSAPKCS1SignatureFormatter(this.Rsa);
                formatter.SetHashAlgorithm(hash.ToString());
                return formatter.CreateSignature(hash.ComputeHash(data));
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            using (var hash = CryptographicEngine.GetHashAlgorithm(this.Algorithm))
            {
                var deformatter = new RSAPKCS1SignatureDeformatter(this.Rsa);
                deformatter.SetHashAlgorithm(hash.ToString());
                return deformatter.VerifySignature(hash.ComputeHash(data), signature);
            }
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            using (var hash = CryptographicEngine.GetHashAlgorithm(this.Algorithm))
            {
                var formatter = new RSAPKCS1SignatureFormatter(this.Rsa);
                formatter.SetHashAlgorithm(hash.ToString());
                return formatter.CreateSignature(data);
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifyHash(byte[] data, byte[] signature)
        {
            try
            {
                using (var hash = CryptographicEngine.GetHashAlgorithm(this.Algorithm))
                {
                    var deformatter = new RSAPKCS1SignatureDeformatter(this.Rsa);
                    deformatter.SetHashAlgorithm(hash.ToString());
                    return deformatter.VerifySignature(data, signature);
                }
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[] iv)
        {
            var keyExchange = new RSAOAEPKeyExchangeFormatter(this.Rsa);
            return keyExchange.CreateKeyExchange(data);
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            var keyExchange = new RSAOAEPKeyExchangeDeformatter(this.Rsa);
            return keyExchange.DecryptKeyExchange(data);
        }
    }
}
