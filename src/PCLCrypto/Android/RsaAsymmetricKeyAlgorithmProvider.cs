// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#if __ANDROID__

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using Android.Runtime;
    using Java.Math;
    using Java.Security;
    using Java.Security.Interfaces;
    using Java.Security.Spec;
    using Microsoft;
    using PCLCrypto.Formatters;

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
        public IReadOnlyList<KeySizes> LegalKeySizes => this.Algorithm.GetTypicalLegalAsymmetricKeySizes();

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            var keyGen = KeyPairGenerator.GetInstance("RSA");
            if (keyGen is null)
            {
                throw new InvalidOperationException(Strings.UnsupportedAlgorithm);
            }

            keyGen.Initialize(keySize);
            var key = keyGen.GenerateKeyPair();
            if (key?.Private is null || key.Public is null)
            {
                throw new InvalidOperationException("GenerateKeyPair returned null or a null components.");
            }

            var privateKeyParameters = key.Private.JavaCast<IRSAPrivateCrtKey>()!;
            var parameters = new RSAParameters
            {
                Modulus = privateKeyParameters.Modulus?.ToByteArray(),
                Exponent = privateKeyParameters.PublicExponent?.ToByteArray(),
                P = privateKeyParameters.PrimeP?.ToByteArray(),
                Q = privateKeyParameters.PrimeQ?.ToByteArray(),
                DP = privateKeyParameters.PrimeExponentP?.ToByteArray(),
                DQ = privateKeyParameters.PrimeExponentQ?.ToByteArray(),
                InverseQ = privateKeyParameters.CrtCoefficient?.ToByteArray(),
                D = privateKeyParameters.PrivateExponent?.ToByteArray(),
            };

            // Normalize RSAParameters (remove leading zeros, etc.)
            parameters = KeyFormatter.Pkcs1.Read(KeyFormatter.Pkcs1.Write(parameters));

            return new RsaCryptographicKey(key.Public, key.Private, parameters, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            Requires.NotNull(keyBlob, nameof(keyBlob));

            RSAParameters parameters = KeyFormatter.GetFormatter(blobType)
                .Read(keyBlob)
                .ComputeFullPrivateKeyData();

            IPrivateKey? privateKey = null;
            IPublicKey? publicKey = null;
            BigInteger? modulus = null, d = null, publicExponent = null;
            RSAPrivateKeySpec? privateKeySpec = null;
            RSAPublicKeySpec? publicKeySpec = null;
            try
            {
#pragma warning disable CA2000 // Dispose objects before losing scope
                modulus = new BigInteger(1, parameters.Modulus);
                d = new BigInteger(1, parameters.D);
                privateKeySpec = new RSAPrivateKeySpec(modulus, d);
                var factory = KeyFactory.GetInstance("RSA");
                if (factory is null)
                {
                    throw new InvalidOperationException(Strings.UnsupportedAlgorithm);
                }

                privateKey = factory.GeneratePrivate(privateKeySpec)!;
                var privateRsaKey = privateKey.JavaCast<IRSAPrivateKey>()!;

                publicExponent = new BigInteger(1, parameters.Exponent);
                publicKeySpec = new RSAPublicKeySpec(privateRsaKey.Modulus, publicExponent);
                publicKey = factory.GeneratePublic(publicKeySpec)!;

                return new RsaCryptographicKey(publicKey, privateKey, parameters, this.algorithm);
#pragma warning restore CA2000 // Dispose objects before losing scope
            }
            catch
            {
                publicExponent?.Dispose();
                publicKeySpec?.Dispose();
                privateKeySpec?.Dispose();
                modulus?.Dispose();
                d?.Dispose();
                privateKey?.Dispose();
                publicKey?.Dispose();
                throw;
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            Requires.NotNull(keyBlob, nameof(keyBlob));

            var parameters = KeyFormatter.GetFormatter(blobType).Read(keyBlob);
            BigInteger? modulus = null, exponent = null;
            RSAPublicKeySpec? spec = null;
            try
            {
#pragma warning disable CA2000 // Dispose objects before losing scope
                modulus = new BigInteger(1, parameters.Modulus);
                exponent = new BigInteger(1, parameters.Exponent);
                spec = new RSAPublicKeySpec(modulus, exponent);
#pragma warning restore CA2000 // Dispose objects before losing scope
                KeyFactory? factory = KeyFactory.GetInstance("RSA");
                if (factory is null)
                {
                    throw new InvalidOperationException(Strings.UnsupportedAlgorithm);
                }

                IPublicKey? publicKey = factory.GeneratePublic(spec);
                if (publicKey is null)
                {
                    throw new InvalidOperationException("KeyFactory.GeneratePublic returned null.");
                }

                return new RsaCryptographicKey(publicKey, parameters, this.algorithm);
            }
            catch
            {
                spec?.Dispose();
                modulus?.Dispose();
                exponent?.Dispose();
                throw;
            }
        }
    }
}

#endif
