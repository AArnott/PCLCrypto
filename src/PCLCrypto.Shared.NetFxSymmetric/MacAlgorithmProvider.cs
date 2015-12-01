// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

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
                    return algorithm.HashSize / 8;
                }
            }
        }

        /// <inheritdoc />
        public CryptographicHash CreateHash(byte[] keyMaterial)
        {
            Requires.NotNull(keyMaterial, "keyMaterial");

            var hash = GetAlgorithm(this.Algorithm);
            hash.Key = keyMaterial;
            return new NetFxCryptographicHash(hash);
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
        internal static Platform.KeyedHashAlgorithm GetAlgorithm(MacAlgorithm algorithm)
        {
#if SILVERLIGHT
            switch (algorithm)
            {
                case MacAlgorithm.HmacSha1:
                    return new Platform.HMACSHA1();
                case MacAlgorithm.HmacSha256:
                    return new Platform.HMACSHA256();
                default:
                    throw new NotSupportedException();
            }
#else
            string algorithmName = MacAlgorithmProviderFactory.GetAlgorithmName(algorithm);
            var result = Platform.KeyedHashAlgorithm.Create(algorithmName);
            if (result == null)
            {
                throw new NotSupportedException();
            }

            return result;
#endif
        }
    }
}
