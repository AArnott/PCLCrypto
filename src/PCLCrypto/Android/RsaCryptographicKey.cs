﻿// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#if __ANDROID__

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Android.Runtime;
    using Java.Security;
    using Java.Security.Interfaces;
    using Javax.Crypto;
    using Microsoft;
    using PCLCrypto.Formatters;

    /// <summary>
    /// The .NET Framework implementation of the <see cref="ICryptographicKey"/> interface
    /// for RSA keys.
    /// </summary>
    internal class RsaCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The platform public key.
        /// </summary>
        private readonly IRSAPublicKey publicKey;

        /// <summary>
        /// The platform private key.
        /// </summary>
        private readonly IRSAPrivateKey? privateKey;

        /// <summary>
        /// The algorithm to use when performing cryptography.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// The RSAParameters to use during export.
        /// </summary>
        private readonly RSAParameters parameters;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="parameters">The RSA instance, if available.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(IPublicKey publicKey, RSAParameters parameters, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, nameof(publicKey));

            this.publicKey = publicKey.JavaCast<IRSAPublicKey>()!;
            this.parameters = parameters;
            this.algorithm = algorithm;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="parameters">The RSA instance, if available.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(IPublicKey publicKey, IPrivateKey privateKey, RSAParameters parameters, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, nameof(publicKey));
            Requires.NotNull(privateKey, nameof(privateKey));

            this.publicKey = publicKey.JavaCast<IRSAPublicKey>()!;
            this.privateKey = privateKey.JavaCast<IRSAPrivateKey>()!;
            this.parameters = parameters;
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.publicKey.Modulus!.BitLength(); }
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
            Verify.Operation(KeyFormatter.HasPrivateKey(this.parameters), "Private key not available.");
            return KeyFormatter.GetFormatter(blobType).Write(this.parameters);
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            return KeyFormatter.GetFormatter(blobType).Write(this.parameters, includePrivateKey: false);
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            using (Signature? instance = Signature.GetInstance(GetSignatureName(this.Algorithm)))
            {
                Verify.Operation(instance is object, "Unable to get signature for algorithm: {0}", this.Algorithm);
                instance.InitVerify(this.publicKey);
                instance.Update(data);
                return instance.Verify(signature);
            }
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            // Please visit this Q&A for a discussion about what we need to make this method work.
            // http://stackoverflow.com/questions/22276976/how-to-sign-based-on-data-but-verify-based-on-hash-in-java/22280659?noredirect=1#22280659
            throw new NotSupportedException();
            ////using (Signature instance = Signature.GetInstance("NONEwithRSA"))
            ////{
            ////    instance.InitSign(this.privateKey);
            ////    instance.Update(data);
            ////    byte[] signature = instance.Sign();
            ////    return signature;
            ////}
        }

        /// <inheritdoc />
        protected internal override bool VerifyHash(byte[] data, byte[] signature)
        {
            // Please visit this Q&A for a discussion about what we need to make this method work.
            // http://stackoverflow.com/questions/22276976/how-to-sign-based-on-data-but-verify-based-on-hash-in-java/22280659?noredirect=1#22280659
            throw new NotSupportedException();
            ////using (Signature instance = Signature.GetInstance("NONEwithRSA"))
            ////{
            ////    instance.InitVerify(this.publicKey);
            ////    instance.Update(data);
            ////    return instance.Verify(signature);
            ////}
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[]? iv)
        {
            using (Cipher? cipher = Cipher.GetInstance(GetCipherName(this.Algorithm)))
            {
                Verify.Operation(cipher is object, "Unable to get cipher for algorithm: {0}", this.Algorithm);
                cipher.Init(Javax.Crypto.CipherMode.EncryptMode, this.publicKey);
                byte[] cipherText = cipher.DoFinal(data)!;
                return cipherText;
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[]? iv)
        {
            Verify.Operation(this.privateKey != null, "Private key missing.");
            using (Cipher? cipher = Cipher.GetInstance(GetCipherName(this.Algorithm)))
            {
                Verify.Operation(cipher is object, "Unable to get cipher for algorithm: {0}", this.Algorithm);
                cipher.Init(Javax.Crypto.CipherMode.DecryptMode, this.privateKey);
                byte[]? plainText = cipher.DoFinal(data)!;
                return plainText;
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            using (Signature? instance = Signature.GetInstance(GetSignatureName(this.Algorithm)))
            {
                Verify.Operation(instance is object, "Unable to get signature for algorithm: {0}", this.Algorithm);
                instance.InitSign(this.privateKey);
                instance.Update(data);
                byte[]? signature = instance.Sign();
                Assumes.NotNull(signature);
                return signature;
            }
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.publicKey?.Dispose();
                this.privateKey?.Dispose();
            }

            base.Dispose(disposing);
        }

        /// <summary>
        /// Gets the string to pass to <see cref="Cipher.GetInstance(string)"/>
        /// for the given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A non-empty string.</returns>
        /// <exception cref="System.NotSupportedException">Thrown if the algorithm isn't supported.</exception>
        private static string GetCipherName(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.RsaOaepSha1:
                    return "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
                case AsymmetricAlgorithm.RsaOaepSha256:
                    return "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
                case AsymmetricAlgorithm.RsaPkcs1:
                    return "RSA/ECB/PKCS1Padding";
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the string to pass to <see cref="Signature.GetInstance(string)"/>
        /// for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A non-empty string.</returns>
        /// <exception cref="System.NotSupportedException">Thrown if the algorithm is not supported.</exception>
        private static string GetSignatureName(AsymmetricAlgorithm algorithm)
        {
            string hashName = HashAlgorithmProviderFactory.GetHashAlgorithmName(AsymmetricKeyAlgorithmProviderFactory.GetHashAlgorithmEnum(algorithm));
            switch (algorithm)
            {
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                    return hashName + "withRSA";
                case AsymmetricAlgorithm.RsaSignPssSha1:
                case AsymmetricAlgorithm.RsaSignPssSha256:
                case AsymmetricAlgorithm.RsaSignPssSha384:
                case AsymmetricAlgorithm.RsaSignPssSha512:
                default:
                    throw new NotSupportedException();
            }
        }
    }
}

#endif
