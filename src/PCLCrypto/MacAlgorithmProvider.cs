// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
#if __ANDROID__
    using Javax.Crypto;
    using Javax.Crypto.Spec;
#endif
    using Microsoft;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The WinRT implementation of the <see cref="IMacAlgorithmProvider"/> interface.
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
#if __ANDROID__
                    return algorithm.MacLength;
#else
                    return algorithm.HashSize / 8;
#endif
                }
            }
        }

        /// <inheritdoc />
        public CryptographicHash CreateHash(byte[] keyMaterial)
        {
            Requires.NotNull(keyMaterial, nameof(keyMaterial));

            var hash = GetAlgorithm(this.Algorithm);
#if __ANDROID__
#pragma warning disable CA2000 // Dispose objects before losing scope
            SecretKeySpec key = GetSecretKey(this.Algorithm, keyMaterial);
#pragma warning restore CA2000 // Dispose objects before losing scope
            try
            {
                hash.Init(key);
                return new JavaCryptographicHashMac(hash);
            }
            catch
            {
                key.Dispose();
                throw;
            }
#else
            hash.Key = keyMaterial;
            return new NetFxCryptographicHash(hash);
#endif
        }

        /// <inheritdoc />
        public ICryptographicKey CreateKey(byte[] keyMaterial)
        {
            return new MacCryptographicKey(this.Algorithm, keyMaterial);
        }

#if __ANDROID__

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
                Mac? result = Mac.GetInstance(algorithmName);
                Assumes.NotNull(result);
                return result;
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

#else
        /// <summary>
        /// Returns the keyed hash algorithm from the platform.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific algorithm.</returns>
        internal static Platform.KeyedHashAlgorithm GetAlgorithm(MacAlgorithm algorithm)
        {
            string algorithmName = MacAlgorithmProviderFactory.GetAlgorithmName(algorithm);
            var result = Platform.KeyedHashAlgorithm.Create(algorithmName);
            if (result == null)
            {
                throw new NotSupportedException();
            }

            return result;
        }
#endif
    }
}
