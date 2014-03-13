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
    using MonoTouch.Security;
    using Validation;

    /// <summary>
    /// The iOS implementation of the <see cref="ICryptographicKey"/> interface
    /// for RSA keys.
    /// </summary>
    internal class RsaCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The platform crypto key.
        /// </summary>
        private readonly SecKey publicKey;

        private readonly SecKey privateKey;

        /// <summary>
        /// The algorithm to use when performing cryptography.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(SecKey publicKey, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, "publicKey");

            this.publicKey = publicKey;
            this.algorithm = algorithm;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(SecKey publicKey, SecKey privateKey, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, "publicKey");
            Requires.NotNull(privateKey, "privateKey");

            this.publicKey = publicKey;
            this.privateKey = privateKey;
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { throw new NotImplementedException(); }
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
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                ////return this.key.ExportCspBlob(includePrivateParameters: true);
                default:
                    throw new NotSupportedException();
            }
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.Capi1PublicKey:
                ////return this.key.ExportCspBlob(includePrivateParameters: false);
                default:
                    throw new NotSupportedException();
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        protected internal override bool VerifyHash(byte[] data, byte[] signature)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[] iv)
        {
            byte[] cipherText;
            var code = this.publicKey.Encrypt(GetPadding(this.Algorithm), data, out cipherText);
            Verify.Operation(code == SecStatusCode.Success, "status was " + code);
            return cipherText;
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            // Initialize a plaintext buffer that is at least as large
            // as the plaintext could possibly be, which is as large as the
            // ciphertext is. Note the resulting plaintext could be smaller
            // as padding may be included in the ciphertext.
            byte[] plainText = new byte[data.Length];

            // BUGBUG: Xamarin.iOS interop API doesn't allow us to determine the
            // actual length of the plaintext after decryption. Padding causes an
            // unpredictable plaintext length to be returned and we rely on the
            // SecKeyDecrypt API's output plainTextLen parameter to tell us, but
            // Xamarin.iOS doesn't hand this back to us.
            var code = this.privateKey.Decrypt(GetPadding(this.Algorithm), data, plainText);
            Verify.Operation(code == SecStatusCode.Success, "status was " + code);
            return plainText;
        }

        /// <summary>
        /// Gets the iOS padding algorithm for a given asymmetric algorithm.
        /// </summary>
        /// <param name="algorithm">The asymmetric algorithm.</param>
        /// <returns>The iOS platform padding enum.</returns>
        private static SecPadding GetPadding(AsymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case AsymmetricAlgorithm.RsaOaepSha1:
                case AsymmetricAlgorithm.RsaOaepSha256:
                case AsymmetricAlgorithm.RsaOaepSha384:
                case AsymmetricAlgorithm.RsaOaepSha512:
                    return SecPadding.OAEP;
                case AsymmetricAlgorithm.RsaPkcs1:
                    return SecPadding.PKCS1;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha1:
                    return SecPadding.PKCS1SHA1;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha256:
                    return SecPadding.PKCS1SHA256;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha384:
                    return SecPadding.PKCS1SHA384;
                case AsymmetricAlgorithm.RsaSignPkcs1Sha512:
                    return SecPadding.PKCS1SHA512;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
