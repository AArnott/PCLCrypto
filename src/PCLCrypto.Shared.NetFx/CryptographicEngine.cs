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
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            var keyClass = (CryptographicKey)key;
            return keyClass.Encrypt(data, iv);
        }

        /// <inheritdoc />
        public ICryptoTransform CreateEncryptor(ICryptographicKey key, byte[] iv)
        {
            Requires.NotNull(key, "key");

            var keyClass = (CryptographicKey)key;
            return keyClass.CreateEncryptor(iv);
        }

        /// <inheritdoc />
        public byte[] Decrypt(ICryptographicKey key, byte[] data, byte[] iv)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            var keyClass = (CryptographicKey)key;
            return keyClass.Decrypt(data, iv);
        }

        /// <inheritdoc />
        public ICryptoTransform CreateDecryptor(ICryptographicKey key, byte[] iv)
        {
            Requires.NotNull(key, "key");

            var keyClass = (CryptographicKey)key;
            return keyClass.CreateDecryptor(iv);
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
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return ((CryptographicKey)key).SignHash(data);
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
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "paramName");

            return ((CryptographicKey)key).VerifyHash(data, signature);
        }

        /// <inheritdoc />
        public byte[] DeriveKeyMaterial(ICryptographicKey key, IKeyDerivationParameters parameters, int desiredKeySize)
        {
            // Right now we're assuming that KdfGenericBinary is directly usable as a salt
            // in RFC2898. When our KeyDerivationParametersFactory class supports
            // more parameter types than just BuildForPbkdf2, we might need to adjust this code
            // to handle each type of parameter.
            var keyDerivation = (KeyDerivationCryptographicKey)key;
            byte[] salt = parameters.KdfGenericBinary;
            switch (keyDerivation.Algorithm)
            {
                case KeyDerivationAlgorithm.Pbkdf2Sha1:
                    var deriveBytes = new Platform.Rfc2898DeriveBytes(keyDerivation.Key, salt, parameters.IterationCount);
                    return deriveBytes.GetBytes(desiredKeySize);
                default:
                    // TODO: consider using Platform.PasswordDeriveBytes if it can
                    // support some more of these algorithms.
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the OID (or name) for a given hash algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A non-empty string.</returns>
        internal static string GetHashAlgorithmOID(AsymmetricAlgorithm algorithm)
        {
            string algorithmName = HashAlgorithmProviderFactory.GetHashAlgorithmName(AsymmetricKeyAlgorithmProviderFactory.GetHashAlgorithmEnum(algorithm));

#if SILVERLIGHT
            // Windows Phone 8.0 and Silverlight both are missing the
            // CryptoConfig type. But that's ok since both platforms
            // accept the algorithm name directly as well as the OID
            // which we can't easily get to.
            return algorithmName;
#else
            // Mono requires the OID, so we get it when we can.
            return Platform.CryptoConfig.MapNameToOID(algorithmName);
#endif
        }

        /// <summary>
        /// Creates a hash algorithm instance that is appropriate for the given algorithm.T
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The hash algorithm.</returns>
#if Android
        internal static Java.Security.MessageDigest GetHashAlgorithm(AsymmetricAlgorithm algorithm)
        {
#else
        internal static Platform.HashAlgorithm GetHashAlgorithm(AsymmetricAlgorithm algorithm)
        {
#endif
            var hashAlgorithm = AsymmetricKeyAlgorithmProviderFactory.GetHashAlgorithmEnum(algorithm);
            return HashAlgorithmProvider.CreateHashAlgorithm(hashAlgorithm);
        }
    }
}
