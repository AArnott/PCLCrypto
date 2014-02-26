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
            return new CryptographicHash(this.Algorithm);
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
#if !WINDOWS_PHONE && !SILVERLIGHT
                case HashAlgorithm.Md5:
                    return Platform.HashAlgorithm.Create("MD5");
                case HashAlgorithm.Sha1:
                    return Platform.HashAlgorithm.Create("SHA1");
                case HashAlgorithm.Sha256:
                    return Platform.HashAlgorithm.Create("SHA256");
                case HashAlgorithm.Sha384:
                    return Platform.HashAlgorithm.Create("SHA384");
                case HashAlgorithm.Sha512:
                    return Platform.HashAlgorithm.Create("SHA512");
#endif
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
