// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
#if Android
    using Java.Security;
#endif
    using Validation;
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
#if Android
                    return hasher.DigestLength;
#else
                    return hasher.HashSize / 8;
#endif
                }
            }
        }

        /// <inheritdoc />
        public CryptographicHash CreateHash()
        {
#if Android
            return new JavaCryptographicHash(CreateHashAlgorithm(this.Algorithm));
#else
            return new NetFxCryptographicHash(CreateHashAlgorithm(this.Algorithm));
#endif
        }

        /// <inheritdoc />
        public byte[] HashData(byte[] data)
        {
            Requires.NotNull(data, "data");

#if Android
            using (var hasher = this.CreateHash())
            {
                hasher.Append(data);
                return hasher.GetValueAndReset();
            }
#else
            using (var hasher = CreateHashAlgorithm(this.Algorithm))
            {
                return hasher.ComputeHash(data);
            }
#endif
        }

#if Android

        /// <summary>
        /// Creates the hash algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>
        /// A platform-specific hash algorithm.
        /// </returns>
        internal static MessageDigest CreateHashAlgorithm(HashAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case HashAlgorithm.Md5:
                    return MessageDigest.GetInstance("MD5");
                case HashAlgorithm.Sha1:
                    return MessageDigest.GetInstance("SHA1");
                case HashAlgorithm.Sha256:
                    return MessageDigest.GetInstance("SHA256");
                case HashAlgorithm.Sha384:
                    return MessageDigest.GetInstance("SHA384");
                case HashAlgorithm.Sha512:
                    return MessageDigest.GetInstance("SHA512");
                default:
                    throw new NotSupportedException();
            }
        }

#else

        /// <summary>
        /// Creates the hash algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>
        /// A platform-specific hash algorithm.
        /// </returns>
        internal static Platform.HashAlgorithm CreateHashAlgorithm(HashAlgorithm algorithm)
        {
#if SILVERLIGHT
            switch (algorithm)
            {
                case HashAlgorithm.Sha1:
                    return new Platform.SHA1Managed();
                case HashAlgorithm.Sha256:
                    return new Platform.SHA256Managed();
                default:
                    throw new NotSupportedException();
           }
#else
            string algorithmName = HashAlgorithmProviderFactory.GetHashAlgorithmName(algorithm);
            return Platform.HashAlgorithm.Create(algorithmName);
#endif
        }

#endif
    }
}
