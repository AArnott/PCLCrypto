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

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="ISymmetricKeyAlgorithmProvider"/>.
        /// </summary>
        private static ISymmetricKeyAlgorithmProviderFactory symmetricKeyAlgorithmProvider;

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IHashAlgorithmProviderFactory"/>.
        /// </summary>
        private static IHashAlgorithmProviderFactory hashAlgorithmProvider;

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IMacAlgorithmProviderFactory"/>.
        /// </summary>
        private static IMacAlgorithmProviderFactory macAlgorithmProvider;

        /// <summary>
        /// Backing field for the CryptographicEngine property.
        /// </summary>
        private static ICryptographicEngine cryptographicEngine;
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

        /// <summary>
        /// Gets the symmetric key algorithm provider factory.
        /// </summary>
        public static ISymmetricKeyAlgorithmProviderFactory SymmetricKeyAlgorithmProvider
        {
            get
            {
#if PCL
                throw new NotImplementedException("Not implemented in reference assembly.");
#else
                if (symmetricKeyAlgorithmProvider == null)
                {
                    symmetricKeyAlgorithmProvider = new SymmetricKeyAlgorithmProviderFactory();
                }

                return symmetricKeyAlgorithmProvider;
#endif
            }
        }

        /// <summary>
        /// Gets the hash algorithm provider factory.
        /// </summary>
        public static IHashAlgorithmProviderFactory HashAlgorithmProvider
        {
            get
            {
#if PCL
                throw new NotImplementedException("Not implemented in reference assembly.");
#else
                if (hashAlgorithmProvider == null)
                {
                    hashAlgorithmProvider = new HashAlgorithmProviderFactory();
                }

                return hashAlgorithmProvider;
#endif
            }
        }

        /// <summary>
        /// Gets the MAC algorithm provider factory.
        /// </summary>
        public static IMacAlgorithmProviderFactory MacAlgorithmProvider
        {
            get
            {
#if PCL
                throw new NotImplementedException("Not implemented in reference assembly.");
#else
                if (macAlgorithmProvider == null)
                {
                    macAlgorithmProvider = new MacAlgorithmProviderFactory();
                }

                return macAlgorithmProvider;
#endif
            }
        }

        /// <summary>
        /// Gets the service for signatures and encryption.
        /// </summary>
        public static ICryptographicEngine CryptographicEngine
        {
            get
            {
#if PCL
                throw new NotImplementedException("Not implemented in reference assembly.");
#else
                if (cryptographicEngine == null)
                {
                    cryptographicEngine = new CryptographicEngine();
                }

                return cryptographicEngine;
#endif
            }
        }
    }
}
