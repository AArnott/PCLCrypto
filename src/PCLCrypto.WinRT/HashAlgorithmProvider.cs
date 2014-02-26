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
    using Validation;
    using Platform = Windows.Security.Cryptography;

    /// <summary>
    /// A WinRT implementation of <see cref="IHashAlgorithmProvider"/>.
    /// </summary>
    internal class HashAlgorithmProvider : IHashAlgorithmProvider
    {
        /// <summary>
        /// The hash algorithm used by this instance.
        /// </summary>
        private readonly HashAlgorithm algorithm;

        /// <summary>
        /// The platform-specific algorithm provider.
        /// </summary>
        private readonly Platform.Core.HashAlgorithmProvider platform;

        /// <summary>
        /// Initializes a new instance of the <see cref="HashAlgorithmProvider" /> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal HashAlgorithmProvider(HashAlgorithm algorithm)
        {
            this.algorithm = algorithm;
            this.platform = Platform.Core.HashAlgorithmProvider.OpenAlgorithm(GetAlgorithmName(algorithm));
        }

        /// <inheritdoc />
        public HashAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public int HashLength
        {
            get { return (int)this.platform.HashLength; }
        }

        /// <inheritdoc />
        public ICryptographicHash CreateHash()
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public byte[] HashData(byte[] data)
        {
            Requires.NotNull(data, "data");

            return this.platform.HashData(data.ToBuffer()).ToArray();
        }

        /// <summary>
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        private static string GetAlgorithmName(HashAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case HashAlgorithm.Md5:
                    return Platform.Core.HashAlgorithmNames.Md5;
                case HashAlgorithm.Sha1:
                    return Platform.Core.HashAlgorithmNames.Sha1;
                case HashAlgorithm.Sha256:
                    return Platform.Core.HashAlgorithmNames.Sha256;
                case HashAlgorithm.Sha384:
                    return Platform.Core.HashAlgorithmNames.Sha384;
                case HashAlgorithm.Sha512:
                    return Platform.Core.HashAlgorithmNames.Sha512;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
