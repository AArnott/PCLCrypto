//-----------------------------------------------------------------------
// <copyright file="Crypto.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Offers access to platform-specific cryptographic functionality.
    /// </summary>
    public static class Crypto
    {
#if !PCL
        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IRandomNumberGenerator"/>.
        /// </summary>
        private static IRandomNumberGenerator randomNumberGenerator;

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IAsymmetricKeyAlgorithmProvider"/>.
        /// </summary>
        private static IAsymmetricKeyAlgorithmProviderFactory asymmetricKeyAlgorithmProvider;
#endif

        /// <summary>
        /// Gets a cryptographically strong random number generator.
        /// </summary>
        public static IRandomNumberGenerator RandomNumberGenerator
        {
            get
            {
#if PCL
                throw new NotImplementedException("Not implemented in reference assembly.");
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
                throw new NotImplementedException("Not implemented in reference assembly.");
#else
                return new DeriveBytes();
#endif
            }
        }

        /// <summary>
        /// Gets the asymmetric key algorithm provider factory.
        /// </summary>
        public static IAsymmetricKeyAlgorithmProviderFactory AsymmetricKeyAlgorithmProvider
        {
            get
            {
#if PCL
                throw new NotImplementedException("Not implemented in reference assembly.");
#else
                if (asymmetricKeyAlgorithmProvider == null)
                {
                    asymmetricKeyAlgorithmProvider = new AsymmetricKeyAlgorithmProviderFactory();
                }

                return asymmetricKeyAlgorithmProvider;
#endif
            }
        }
    }
}
