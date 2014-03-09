//-----------------------------------------------------------------------
// <copyright file="RsaAsymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Android.Runtime;
    using Java.Math;
    using Java.Security;
    using Java.Security.Interfaces;
    using Java.Security.Spec;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The .NET Framework implementation of RSA.
    /// </summary>
    internal class RsaAsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public RsaAsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc/>
        public AsymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            var keyGen = KeyPairGenerator.GetInstance("RSA");
            keyGen.Initialize(keySize);
            var key = keyGen.GenerateKeyPair();

            return new RsaCryptographicKey(key.Public, key.Private, null, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            System.Security.Cryptography.RSACryptoServiceProvider rsa=null;
            IPrivateKey privateKey;
            IPublicKey publicKey;
            switch (blobType)
            {
                case CryptographicPrivateKeyBlobType.Capi1PrivateKey:
                    {
                        rsa = new System.Security.Cryptography.RSACryptoServiceProvider();
                        rsa.ImportCspBlob(keyBlob);
                        var p = rsa.ExportParameters(true);

                        var spec = new RSAPrivateKeySpec(new BigInteger(p.Modulus), new BigInteger(p.D));
                        var factory = KeyFactory.GetInstance("RSA");
                        privateKey = factory.GeneratePrivate(spec);

                        var privateRsaKey = privateKey.JavaCast<IRSAPrivateKey>();
                        var publicKeySpec = new RSAPublicKeySpec(privateRsaKey.Modulus, new BigInteger(p.Exponent));
                        publicKey = factory.GeneratePublic(publicKeySpec);
                        break;
                    }
                case CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo:
                    {
                        var spec = new PKCS8EncodedKeySpec(keyBlob);
                        var factory = KeyFactory.GetInstance("RSA");
                        privateKey = factory.GeneratePrivate(spec);

                        var privateRsaKey = privateKey.JavaCast<IRSAPrivateKey>();
                        var publicKeySpec = new RSAPublicKeySpec(privateRsaKey.Modulus, BigInteger.ValueOf(0x10001)); // TODO: replace 65537 with actual public exponent.
                        publicKey = factory.GeneratePublic(publicKeySpec);
                        break;
                    }
                default:
                    throw new NotSupportedException();
            }

            return new RsaCryptographicKey(publicKey, privateKey, rsa, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            IPublicKey publicKey;
            switch (blobType)
            {
                case CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo:
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBlob);
                    KeyFactory factory = KeyFactory.GetInstance("RSA");
                    publicKey = factory.GeneratePublic(spec);
                    break;
                default:
                    throw new NotSupportedException();
            }

            return new RsaCryptographicKey(publicKey, this.algorithm);
        }
    }
}
