// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// A WinRT implementation of <see cref="IHashAlgorithmProviderFactory"/>.
    /// </summary>
    internal class HashAlgorithmProviderFactory : IHashAlgorithmProviderFactory
    {
        /// <inheritdoc />
        public IHashAlgorithmProvider OpenAlgorithm(HashAlgorithm algorithm)
        {
            return new HashAlgorithmProvider(algorithm);
        }

        /// <summary>
        /// Gets the name for a given hash algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A non-empty string.</returns>
        internal static string GetHashAlgorithmName(HashAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case HashAlgorithm.Md5:
                    return "MD5";
                case HashAlgorithm.Sha1:
                    return "SHA1";
                case HashAlgorithm.Sha256:
                    return "SHA256";
                case HashAlgorithm.Sha384:
                    return "SHA384";
                case HashAlgorithm.Sha512:
                    return "SHA512";
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
