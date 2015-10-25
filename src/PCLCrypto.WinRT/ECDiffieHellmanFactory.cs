// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using PInvoke;
    using static PInvoke.BCrypt;

    /// <summary>
    /// The WinRT implementation of the <see cref="IECDiffieHellmanFactory"/>.
    /// </summary>
    internal class ECDiffieHellmanFactory : IECDiffieHellmanFactory
    {
        /// <summary>
        /// Key sizes and the name of the algorithm that supports them.
        /// </summary>
        internal static readonly IReadOnlyDictionary<int, string> EcdhKeySizesAndAlgorithmNames = new Dictionary<int, string>
        {
            { 256, "ECDH_P256" },
            { 384, "ECDH_P384" },
            { 521, "ECDH_P521" },
        };

        /// <inheritdoc />
        public IECDiffieHellman Create()
        {
            return new ECDiffieHellman();
        }

        /// <summary>
        /// Opens a BCrypt algorithm.
        /// </summary>
        /// <param name="keySize">The length of the key, in bits.</param>
        /// <returns>The BCrypt algorithm.</returns>
        internal static SafeAlgorithmHandle BCryptOpenAlgorithmProvider(int keySize)
        {
            SafeAlgorithmHandle algorithm;
            BCrypt.BCryptOpenAlgorithmProvider(
                out algorithm,
                EcdhKeySizesAndAlgorithmNames[keySize],
                null,
                BCryptOpenAlgorithmProviderFlags.None).ThrowOnError();
            return algorithm;
        }
    }
}
