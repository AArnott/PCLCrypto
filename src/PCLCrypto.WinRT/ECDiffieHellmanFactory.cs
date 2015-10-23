//-----------------------------------------------------------------------
// <copyright file="ECDiffieHellmanFactory.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

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
        /// <inheritdoc />
        public IECDiffieHellman Create()
        {
            return new ECDiffieHellman();
        }

        internal static readonly IReadOnlyDictionary<int, string> ECDH_KeySizesAndAlgorithmNames = new Dictionary<int, string>
        {
            { 256, "ECDH_P256" },
            { 384, "ECDH_P384" },
            { 521, "ECDH_P521" },
        };

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
                ECDH_KeySizesAndAlgorithmNames[keySize],
                null,
                BCryptOpenAlgorithmProviderFlags.None).ThrowOnError();
            return algorithm;
        }
    }
}
