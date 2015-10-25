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
    /// .NET Framework implementation of the <see cref="IAsymmetricKeyAlgorithmProviderFactory"/> interface.
    /// </summary>
    internal class AsymmetricKeyAlgorithmProviderFactory : IAsymmetricKeyAlgorithmProviderFactory
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyAlgorithmProviderFactory"/> class.
        /// </summary>
        public AsymmetricKeyAlgorithmProviderFactory()
        {
        }

        /// <inheritdoc />
        public IAsymmetricKeyAlgorithmProvider OpenAlgorithm(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
#if DESKTOP
                case AsymmetricAlgorithm.DsaSha1:
                case AsymmetricAlgorithm.DsaSha256:
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                    return new CngAsymmetricKeyAlgorithmProvider(algorithm);
#endif
#if !SILVERLIGHT || WINDOWS_PHONE
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaOaepSha512:
                case AsymmetricAlgorithm.RsaPkcs1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                case AsymmetricAlgorithm.RsaSignPssSha1:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    return new RsaAsymmetricKeyAlgorithmProvider(algorithm);
#endif
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the hash algorithm for a given asymmetric algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A hash algorithm.</returns>
        internal static HashAlgorithm GetHashAlgorithmEnum(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.DsaSha1:
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPssSha1:
                    return HashAlgorithm.Sha1;
                case AsymmetricAlgorithm.DsaSha256:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                    return HashAlgorithm.Sha256;
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                    return HashAlgorithm.Sha384;
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                case AsymmetricAlgorithm.RsaOaepSha512:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    return HashAlgorithm.Sha512;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
