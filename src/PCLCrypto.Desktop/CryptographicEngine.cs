//-----------------------------------------------------------------------
// <copyright file="CryptographicEngine.cs" company="Andrew Arnott">
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
    /// A .NET Framework implementation of <see cref="ICryptographicEngine"/>.
    /// </summary>
    internal class CryptographicEngine : ICryptographicEngine
    {
        /// <inheritdoc />
        public byte[] Encrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public byte[] Decrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public byte[] Sign(ICryptographicKey key, byte[] data)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return ((CryptographicKey)key).Sign(data);
        }

        /// <inheritdoc />
        public byte[] SignHashedData(ICryptographicKey key, byte[] data)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public bool VerifySignature(ICryptographicKey key, byte[] data, byte[] signature)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "signature");

            return ((CryptographicKey)key).VerifySignature(data, signature);
        }

        /// <inheritdoc />
        public bool VerifySignatureWithHashInput(ICryptographicKey key, byte[] data, byte[] signature)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Creates a hash algorithm instance that is appropriate for the given algorithm.T
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The hash algorithm.</returns>
        internal static Platform.HashAlgorithm GetHashAlgorithm(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.DsaSha1:
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPssSha1:
                    return Platform.HashAlgorithm.Create("SHA1");
                case AsymmetricAlgorithm.DsaSha256:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.EcdsaP256Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                    return Platform.HashAlgorithm.Create("SHA256");
                case AsymmetricAlgorithm.EcdsaP384Sha384:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                    return Platform.HashAlgorithm.Create("SHA384");
                case AsymmetricAlgorithm.EcdsaP521Sha512:
                case AsymmetricAlgorithm.RsaOaepSha512:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                    return Platform.HashAlgorithm.Create("SHA512");
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
