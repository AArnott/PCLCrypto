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
    using Java.Security;
#endif
    using Microsoft;
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
#if __ANDROID__
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
#if __ANDROID__
            return new JavaCryptographicHash(CreateHashAlgorithm(this.Algorithm));
#else
            return new NetFxCryptographicHash(CreateHashAlgorithm(this.Algorithm));
#endif
        }

        /// <inheritdoc />
        public byte[] HashData(byte[] data)
        {
            Requires.NotNull(data, nameof(data));

#if __ANDROID__
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

#if __ANDROID__

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
                    return MessageDigest.GetInstance("MD5") ?? throw new PlatformNotSupportedException("MessageDigest.GetInstance(string) returned null.");
                case HashAlgorithm.Sha1:
                    return MessageDigest.GetInstance("SHA1") ?? throw new PlatformNotSupportedException("MessageDigest.GetInstance(string) returned null.");
                case HashAlgorithm.Sha256:
                    return MessageDigest.GetInstance("SHA256") ?? throw new PlatformNotSupportedException("MessageDigest.GetInstance(string) returned null.");
                case HashAlgorithm.Sha384:
                    return MessageDigest.GetInstance("SHA384") ?? throw new PlatformNotSupportedException("MessageDigest.GetInstance(string) returned null.");
                case HashAlgorithm.Sha512:
                    return MessageDigest.GetInstance("SHA512") ?? throw new PlatformNotSupportedException("MessageDigest.GetInstance(string) returned null.");
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
            string algorithmName = HashAlgorithmProviderFactory.GetHashAlgorithmName(algorithm);
            return Platform.HashAlgorithm.Create(algorithmName);
        }

#endif
    }
}
