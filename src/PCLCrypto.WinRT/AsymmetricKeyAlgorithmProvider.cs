//-----------------------------------------------------------------------
// <copyright file="AsymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
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
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// WinRT implementation of the <see cref="IAsymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    public class AsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The WinRT platform implementation.
        /// </summary>
        private readonly Platform.AsymmetricKeyAlgorithmProvider platform;

        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public AsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
            this.platform = Platform.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(GetAlgorithmName(algorithm));
        }

        /// <inheritdoc/>
        public AsymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyPair)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        private static string GetAlgorithmName(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.DsaSha1:
                    return Platform.AsymmetricAlgorithmNames.DsaSha1;
                case AsymmetricAlgorithm.DsaSha256:
                    return Platform.AsymmetricAlgorithmNames.DsaSha256;
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                    return Platform.AsymmetricAlgorithmNames.EcdsaP256Sha256;
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                    return Platform.AsymmetricAlgorithmNames.EcdsaP384Sha384;
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                    return Platform.AsymmetricAlgorithmNames.EcdsaP521Sha512;
                case AsymmetricAlgorithm.RsaOaepSha1:
                    return Platform.AsymmetricAlgorithmNames.RsaOaepSha1;
                case AsymmetricAlgorithm.RsaOaepSha256:
                    return Platform.AsymmetricAlgorithmNames.RsaOaepSha256;
                case AsymmetricAlgorithm.RsaOaepSha384:
                    return Platform.AsymmetricAlgorithmNames.RsaOaepSha384;
                case AsymmetricAlgorithm.RsaOaepSha512:
                    return Platform.AsymmetricAlgorithmNames.RsaOaepSha512;
                case AsymmetricAlgorithm.RsaPkcs1:
                    return Platform.AsymmetricAlgorithmNames.RsaPkcs1;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPkcs1Sha1;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPkcs1Sha256;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPkcs1Sha384;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPkcs1Sha512;
                case AsymmetricAlgorithm.RsaSignPssSha1:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPssSha1;
                case AsymmetricAlgorithm.RsaSignPssSha256:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPssSha256;
                case AsymmetricAlgorithm.RsaSignPssSha384:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPssSha384;
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    return Platform.AsymmetricAlgorithmNames.RsaSignPssSha512;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
