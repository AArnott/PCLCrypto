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
    using Java.Security;
    using Java.Security.Interfaces;
    using Javax.Crypto;
    using Validation;
    using Android.Runtime;

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
        private readonly IRSAPrivateKey privateKey;

        /// <summary>
        /// The algorithm to use when performing cryptography.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(IPublicKey publicKey, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, "publicKey");

            this.publicKey = publicKey.JavaCast<IRSAPublicKey>();
            this.algorithm = algorithm;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaCryptographicKey" /> class.
        /// </summary>
        /// <param name="publicKey">The public key.</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="algorithm">The algorithm.</param>
        internal RsaCryptographicKey(IPublicKey publicKey, IPrivateKey privateKey, AsymmetricAlgorithm algorithm)
        {
            Requires.NotNull(publicKey, "publicKey");
            Requires.NotNull(privateKey, "privateKey");

            this.publicKey = publicKey.JavaCast<IRSAPublicKey>();
            this.privateKey = privateKey.JavaCast<IRSAPrivateKey>();
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.publicKey.Modulus.BitLength(); }
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
                case CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo:
                    Verify.Operation(this.privateKey != null, "No private key.");
                    return this.privateKey.GetEncoded();
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
                    return this.publicKey.GetEncoded();
                default:
                    throw new NotSupportedException();
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Sign(byte[] data)
        {
            // TODO: Replace "SHA1" below with whatever the appropriate hash is.
            using (Signature instance = Signature.GetInstance("SHA1withRSA"))
            {
                instance.InitSign(this.privateKey);
                instance.Update(data);
                byte[] signature = instance.Sign();
                return signature;
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifySignature(byte[] data, byte[] signature)
        {
            // TODO: Replace "SHA1" below with whatever the appropriate hash is.
            using (Signature instance = Signature.GetInstance("SHA1withRSA"))
            {
                instance.InitVerify(this.publicKey);
                instance.Update(data);
                return instance.Verify(signature);
            }
        }

        /// <inheritdoc />
        protected internal override byte[] SignHash(byte[] data)
        {
            using (Signature instance = Signature.GetInstance("NONEwithRSA"))
            {
                instance.InitSign(this.privateKey);
                instance.Update(data);
                byte[] signature = instance.Sign();
                return signature;
            }
        }

        /// <inheritdoc />
        protected internal override bool VerifyHash(byte[] data, byte[] signature)
        {
            using (Signature instance = Signature.GetInstance("NONEwithRSA"))
            {
                instance.InitVerify(this.publicKey);
                instance.Update(data);
                return instance.Verify(signature);
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[] iv)
        {
            using (Cipher cipher = Cipher.GetInstance("RSA"))
            {
                cipher.Init(Javax.Crypto.CipherMode.EncryptMode, this.publicKey);
                byte[] cipherText = cipher.DoFinal(data);
                return cipherText;
            }
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            Verify.Operation(this.privateKey != null, "Private key missing.");
            using (Cipher cipher = Cipher.GetInstance("RSA"))
            {
                cipher.Init(Javax.Crypto.CipherMode.DecryptMode, this.privateKey);
                byte[] plainText = cipher.DoFinal(data);
                return plainText;
            }
        }
    }
}
