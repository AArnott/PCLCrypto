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
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using Android.Runtime;
    using Java.Math;
    using Java.Security;
    using Java.Security.Interfaces;
    using Java.Security.Spec;
    using PCLCrypto.Formatters;
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

            var privateKeyParameters = key.Private.JavaCast<IRSAPrivateCrtKey>();
            var parameters = new RSAParameters
            {
                Modulus = privateKeyParameters.Modulus.ToByteArray(),
                Exponent = privateKeyParameters.PublicExponent.ToByteArray(),
                P = privateKeyParameters.PrimeP.ToByteArray(),
                Q = privateKeyParameters.PrimeQ.ToByteArray(),
                DP = privateKeyParameters.PrimeExponentP.ToByteArray(),
                DQ = privateKeyParameters.PrimeExponentQ.ToByteArray(),
                InverseQ = privateKeyParameters.CrtCoefficient.ToByteArray(),
                D = privateKeyParameters.PrivateExponent.ToByteArray(),
            };

            return new RsaCryptographicKey(key.Public, key.Private, parameters, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            RSAParameters parameters = KeyFormatter.GetFormatter(blobType).Read(keyBlob);
            IPrivateKey privateKey;
            IPublicKey publicKey;

            var spec = new RSAPrivateKeySpec(new BigInteger(1, parameters.Modulus), new BigInteger(1, parameters.D));
            var factory = KeyFactory.GetInstance("RSA");
            privateKey = factory.GeneratePrivate(spec);

            var privateRsaKey = privateKey.JavaCast<IRSAPrivateKey>();
            var publicKeySpec = new RSAPublicKeySpec(privateRsaKey.Modulus, new BigInteger(1, parameters.Exponent));
            publicKey = factory.GeneratePublic(publicKeySpec);

            return new RsaCryptographicKey(publicKey, privateKey, parameters, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            var parameters = KeyFormatter.GetFormatter(blobType).Read(keyBlob);
            var spec = new RSAPublicKeySpec(new BigInteger(1, parameters.Modulus), new BigInteger(1, parameters.Exponent));
            KeyFactory factory = KeyFactory.GetInstance("RSA");
            IPublicKey publicKey = factory.GeneratePublic(spec);
            return new RsaCryptographicKey(publicKey, parameters, this.algorithm);
        }
    }
}
