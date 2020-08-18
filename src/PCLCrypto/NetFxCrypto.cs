// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Exposes cryptography using API familiar to .NET Framework developers.
    /// </summary>
    public static class NetFxCrypto
    {
        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IRandomNumberGenerator"/>.
        /// </summary>
        private static IRandomNumberGenerator? randomNumberGenerator;

        /// <summary>
        /// Gets a cryptographically strong random number generator.
        /// </summary>
        public static IRandomNumberGenerator RandomNumberGenerator
        {
            get
            {
                if (randomNumberGenerator == null)
                {
                    randomNumberGenerator = new RandomNumberGenerator();
                }

                return randomNumberGenerator;
            }
        }

        /// <summary>
        /// Gets tools to derive a key from a password for buffer.
        /// </summary>
        public static IDeriveBytes DeriveBytes
        {
            get
            {
                return new DeriveBytes();
            }
        }

        /// <summary>
        /// Gets the factory for <see cref="IECDiffieHellman"/> instances.
        /// </summary>
        public static IECDiffieHellmanFactory ECDiffieHellman
        {
            get
            {
                return new ECDiffieHellmanFactory();
            }
        }

        /// <summary>
        /// Gets the factory for <see cref="IECDiffieHellmanPublicKey"/> instances.
        /// </summary>
        public static IECDiffieHellmanCngPublicKeyFactory ECDiffieHellmanCngPublicKey
        {
            get
            {
                return new ECDiffieHellmanCngPublicKeyFactory();
            }
        }
    }
}
