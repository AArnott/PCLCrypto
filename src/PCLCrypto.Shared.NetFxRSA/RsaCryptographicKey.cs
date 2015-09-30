﻿//-----------------------------------------------------------------------
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
                AsymmetricSignatureFormatter formatter = this.GetSignatureFormatter();
                formatter.SetHashAlgorithm(hash.ToString());
                return formatter.CreateSignature(hash.ComputeHash(data));
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            using (var hash = CryptographicEngine.GetHashAlgorithm(this.Algorithm))
            {
                var deformatter = this.GetSignatureDeformatter();
                deformatter.SetHashAlgorithm(hash.ToString());
                return deformatter.VerifySignature(hash.ComputeHash(data), signature);
            }
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            using (var hash = CryptographicEngine.GetHashAlgorithm(this.Algorithm))
            {
                var formatter = this.GetSignatureFormatter();
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
                    var deformatter = this.GetSignatureDeformatter();
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
            AsymmetricKeyExchangeFormatter keyExchange;
            switch (this.Algorithm)
            {
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaOaepSha512:
                    keyExchange = new RSAOAEPKeyExchangeFormatter(this.Rsa);
                    break;
                case AsymmetricAlgorithm.RsaPkcs1:
                    keyExchange = new RSAPKCS1KeyExchangeFormatter(this.Rsa);
                    break;
                default:
                    throw new NotSupportedException();
            }

            return keyExchange.CreateKeyExchange(data);
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            AsymmetricKeyExchangeDeformatter keyExchange;
            switch (this.Algorithm)
            {
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaOaepSha512:
                    keyExchange = new RSAOAEPKeyExchangeDeformatter(this.Rsa);
                    break;
                case AsymmetricAlgorithm.RsaPkcs1:
                    keyExchange = new RSAPKCS1KeyExchangeDeformatter(this.Rsa);
                    break;
                default:
                    throw new NotSupportedException();
            }

            return keyExchange.DecryptKeyExchange(data);
        }

        /// <summary>
        /// Gets the signature formatter for the selected algorithm.
        /// </summary>
        /// <returns>A signature formatter.</returns>
        /// <exception cref="NotSupportedException">Thrown if the platform does not support the selected algorithm.</exception>
        private AsymmetricSignatureFormatter GetSignatureFormatter()
        {
            AsymmetricSignatureFormatter formatter;
            switch (this.Algorithm)
            {
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                    formatter = new RSAPKCS1SignatureFormatter(this.Rsa);
                    break;
                case AsymmetricAlgorithm.RsaSignPssSha1:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                default:
                    throw new NotSupportedException();
            }

            return formatter;
        }

        /// <summary>
        /// Gets the signature deformatter for the selected algorithm.
        /// </summary>
        /// <returns>A signature deformatter.</returns>
        /// <exception cref="NotSupportedException">Thrown if the platform does not support the selected algorithm.</exception>
        private AsymmetricSignatureDeformatter GetSignatureDeformatter()
        {
            AsymmetricSignatureDeformatter formatter;
            switch (this.Algorithm)
            {
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                    formatter = new RSAPKCS1SignatureDeformatter(this.Rsa);
                    break;
                case AsymmetricAlgorithm.RsaSignPssSha1:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                default:
                    throw new NotSupportedException();
            }

            return formatter;
        }
    }
}
