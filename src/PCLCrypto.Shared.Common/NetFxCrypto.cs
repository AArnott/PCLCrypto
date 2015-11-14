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
#if !PCL

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IRandomNumberGenerator"/>.
        /// </summary>
        private static IRandomNumberGenerator randomNumberGenerator;
#endif

        /// <summary>
        /// Gets a cryptographically strong random number generator.
        /// </summary>
        public static IRandomNumberGenerator RandomNumberGenerator
        {
            get
            {
#if PCL
                throw new NotImplementedByReferenceAssemblyException();
#else
                if (randomNumberGenerator == null)
                {
                    randomNumberGenerator = new RandomNumberGenerator();
                }

                return randomNumberGenerator;
#endif
            }
        }

        /// <summary>
        /// Gets tools to derive a key from a password for buffer.
        /// </summary>
        public static IDeriveBytes DeriveBytes
        {
            get
            {
#if PCL
                throw new NotImplementedByReferenceAssemblyException();
#else
                return new DeriveBytes();
#endif
            }
        }

        /// <summary>
        /// Gets the factory for <see cref="IECDiffieHellman"/> instances.
        /// </summary>
        public static IECDiffieHellmanFactory ECDiffieHellman
        {
            get
            {
#if PCL
                throw new NotImplementedByReferenceAssemblyException();
#elif !SILVERLIGHT
                return new ECDiffieHellmanFactory();
#else
                throw new NotSupportedException();
#endif
            }
        }

        /// <summary>
        /// Gets the factory for <see cref="IECDiffieHellmanPublicKey"/> instances.
        /// </summary>
        public static IECDiffieHellmanCngPublicKeyFactory ECDiffieHellmanCngPublicKey
        {
            get
            {
#if PCL
                throw new NotImplementedByReferenceAssemblyException();
#elif !SILVERLIGHT
                return new ECDiffieHellmanCngPublicKeyFactory();
#else
                throw new NotSupportedException();
#endif
            }
        }
    }
}
