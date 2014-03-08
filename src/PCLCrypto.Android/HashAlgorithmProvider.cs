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
    using Java.Security;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The Java implementation of <see cref="IHashAlgorithmProvider"/>.
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
                using (var hash = CreateHashAlgorithm(this.Algorithm))
                {
                    return hash.DigestLength;
                }
            }
        }

        /// <inheritdoc />
        public CryptographicHash CreateHash()
        {
            return new JavaCryptographicHash(CreateHashAlgorithm(this.Algorithm));
        }

        /// <inheritdoc />
        public byte[] HashData(byte[] data)
        {
            Requires.NotNull(data, "data");

            using (var hasher = CreateHash())
            {
                hasher.Append(data);
                return hasher.GetValueAndReset();
            }
        }

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
    }
}
