// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Javax.Crypto;
    using Javax.Crypto.Spec;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The Android implementation of the <see cref="IMacAlgorithmProvider"/> interface.
    /// </summary>
    internal class MacAlgorithmProvider : IMacAlgorithmProvider
    {
        /// <summary>
        /// The algorithm of this instance.
        /// </summary>
        private readonly MacAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="MacAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal MacAlgorithmProvider(MacAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public MacAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public int MacLength
        {
            get
            {
                using (var algorithm = GetAlgorithm(this.Algorithm))
                {
                    return algorithm.MacLength;
                }
            }
        }

        /// <inheritdoc />
        public CryptographicHash CreateHash(byte[] keyMaterial)
        {
            Requires.NotNull(keyMaterial, "keyMaterial");

            var hash = GetAlgorithm(this.Algorithm);
            hash.Init(GetSecretKey(this.Algorithm, keyMaterial));
            return new JavaCryptographicHashMac(hash);
        }

        /// <inheritdoc />
        public ICryptographicKey CreateKey(byte[] keyMaterial)
        {
            return new MacCryptographicKey(this.Algorithm, keyMaterial);
        }

        /// <summary>
        /// Returns the keyed hash algorithm from the platform.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific algorithm.</returns>
        internal static Mac GetAlgorithm(MacAlgorithm algorithm)
        {
            string algorithmName = MacAlgorithmProviderFactory.GetAlgorithmName(algorithm);
            try
            {
                return Mac.GetInstance(algorithmName);
            }
            catch (Java.Security.NoSuchAlgorithmException ex)
            {
                throw new NotSupportedException(ex.Message, ex);
            }
        }

        /// <summary>
        /// Returns the secret key to use for initializing the Mac.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="keyMaterial">The key material.</param>
        /// <returns>The secret key.</returns>
        internal static SecretKeySpec GetSecretKey(MacAlgorithm algorithm, byte[] keyMaterial)
        {
            string algorithmName = MacAlgorithmProviderFactory.GetAlgorithmName(algorithm);
            var signingKey = new SecretKeySpec(keyMaterial, algorithmName);
            return signingKey;
        }
    }
}
