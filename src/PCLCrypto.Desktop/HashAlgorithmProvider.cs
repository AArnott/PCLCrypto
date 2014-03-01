//-----------------------------------------------------------------------
// <copyright file="HashAlgorithmProvider.cs" company="Andrew Arnott">
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
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The .NET Framework implementation of <see cref="IHashAlgorithmProvider"/>.
    /// </summary>
    internal class HashAlgorithmProvider : IHashAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly HashAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="HashAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal HashAlgorithmProvider(HashAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public HashAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public int HashLength
        {
            get
            {
                using (var hasher = CreateHashAlgorithm(this.Algorithm))
                {
                    return hasher.HashSize / 8;
                }
            }
        }

        /// <inheritdoc />
        public ICryptographicHash CreateHash()
        {
            return new CryptographicHashPlain(this.Algorithm);
        }

        /// <inheritdoc />
        public byte[] HashData(byte[] data)
        {
            using (var hasher = CreateHashAlgorithm(this.Algorithm))
            {
                return hasher.ComputeHash(data);
            }
        }

        /// <summary>
        /// Creates the hash algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>
        /// A platform-specific hash algorithm.
        /// </returns>
        internal static Platform.HashAlgorithm CreateHashAlgorithm(HashAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case HashAlgorithm.Md5:
#if SILVERLIGHT
                    throw new NotSupportedException();
#else
                    return Platform.HashAlgorithm.Create("MD5");
#endif
                case HashAlgorithm.Sha1:
#if SILVERLIGHT
                    return new Platform.SHA1Managed();
#else
                    return Platform.HashAlgorithm.Create("SHA1");
#endif
                case HashAlgorithm.Sha256:
#if SILVERLIGHT
                    return new Platform.SHA256Managed();
#else
                    return Platform.HashAlgorithm.Create("SHA256");
#endif
                case HashAlgorithm.Sha384:
#if !SILVERLIGHT
                    return Platform.HashAlgorithm.Create("SHA384");
#endif
                case HashAlgorithm.Sha512:
#if !SILVERLIGHT
                    return Platform.HashAlgorithm.Create("SHA512");
#endif
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
