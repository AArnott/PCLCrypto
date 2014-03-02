//-----------------------------------------------------------------------
// <copyright file="MacAlgorithmProvider.cs" company="Andrew Arnott">
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
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        internal static Platform.KeyedHashAlgorithm GetAlgorithm(MacAlgorithm algorithm)
        {
            switch (algorithm)
            {
#if !SILVERLIGHT
                case MacAlgorithm.AesCmac:
                    return Platform.KeyedHashAlgorithm.Create("AesCmac");
                case MacAlgorithm.HmacMd5:
                    return Platform.KeyedHashAlgorithm.Create("HmacMd5");
#endif
                case MacAlgorithm.HmacSha1:
#if SILVERLIGHT
                    return new Platform.HMACSHA1();
#else
                    return Platform.KeyedHashAlgorithm.Create("HmacSha1");
#endif
                case MacAlgorithm.HmacSha256:
#if SILVERLIGHT
                    return new Platform.HMACSHA256();
#else
                    return Platform.KeyedHashAlgorithm.Create("HmacSha256");
#endif
#if !SILVERLIGHT
                case MacAlgorithm.HmacSha384:
                    return Platform.KeyedHashAlgorithm.Create("HmacSha384");
                case MacAlgorithm.HmacSha512:
                    return Platform.KeyedHashAlgorithm.Create("HmacSha512");
#endif
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
