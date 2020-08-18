﻿// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Exposes cryptography using API familiar to WinRT developers.
    /// </summary>
    public static class WinRTCrypto
    {
        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IAsymmetricKeyAlgorithmProvider"/>.
        /// </summary>
        private static IAsymmetricKeyAlgorithmProviderFactory? asymmetricKeyAlgorithmProvider;

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="ISymmetricKeyAlgorithmProvider"/>.
        /// </summary>
        private static ISymmetricKeyAlgorithmProviderFactory? symmetricKeyAlgorithmProvider;

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IHashAlgorithmProviderFactory"/>.
        /// </summary>
        private static IHashAlgorithmProviderFactory? hashAlgorithmProvider;

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IMacAlgorithmProviderFactory"/>.
        /// </summary>
        private static IMacAlgorithmProviderFactory? macAlgorithmProvider;

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IKeyDerivationAlgorithmProviderFactory"/>.
        /// </summary>
        private static IKeyDerivationAlgorithmProviderFactory? keyDerivationAlgorithmProvider;

        /// <summary>
        /// Backing field storing a shareable, thread-safe implementation
        /// of <see cref="IKeyDerivationParametersFactory"/>.
        /// </summary>
        private static IKeyDerivationParametersFactory? keyDerivationParametersFactory;

        /// <summary>
        /// Backing field for the CryptographicEngine property.
        /// </summary>
        private static ICryptographicEngine? cryptographicEngine;

        /// <summary>
        /// Backing field for the CryptographicBuffer property.
        /// </summary>
        private static ICryptographicBuffer? cryptographicBuffer;

        /// <summary>
        /// Gets the asymmetric key algorithm provider factory.
        /// </summary>
        public static IAsymmetricKeyAlgorithmProviderFactory AsymmetricKeyAlgorithmProvider
        {
            get
            {
                if (asymmetricKeyAlgorithmProvider == null)
                {
                    asymmetricKeyAlgorithmProvider = new AsymmetricKeyAlgorithmProviderFactory();
                }

                return asymmetricKeyAlgorithmProvider;
            }
        }

        /// <summary>
        /// Gets the symmetric key algorithm provider factory.
        /// </summary>
        public static ISymmetricKeyAlgorithmProviderFactory SymmetricKeyAlgorithmProvider
        {
            get
            {
                if (symmetricKeyAlgorithmProvider == null)
                {
                    symmetricKeyAlgorithmProvider = new SymmetricKeyAlgorithmProviderFactory();
                }

                return symmetricKeyAlgorithmProvider;
            }
        }

        /// <summary>
        /// Gets the hash algorithm provider factory.
        /// </summary>
        public static IHashAlgorithmProviderFactory HashAlgorithmProvider
        {
            get
            {
                if (hashAlgorithmProvider == null)
                {
                    hashAlgorithmProvider = new HashAlgorithmProviderFactory();
                }

                return hashAlgorithmProvider;
            }
        }

        /// <summary>
        /// Gets the MAC algorithm provider factory.
        /// </summary>
        public static IMacAlgorithmProviderFactory MacAlgorithmProvider
        {
            get
            {
                if (macAlgorithmProvider == null)
                {
                    macAlgorithmProvider = new MacAlgorithmProviderFactory();
                }

                return macAlgorithmProvider;
            }
        }

        /// <summary>
        /// Gets the key derivation algorithm provider factory.
        /// </summary>
        public static IKeyDerivationAlgorithmProviderFactory KeyDerivationAlgorithmProvider
        {
            get
            {
                if (keyDerivationAlgorithmProvider == null)
                {
                    keyDerivationAlgorithmProvider = new KeyDerivationAlgorithmProviderFactory();
                }

                return keyDerivationAlgorithmProvider;
            }
        }

        /// <summary>
        /// Gets the key derivation parameters factory.
        /// </summary>
        public static IKeyDerivationParametersFactory KeyDerivationParameters
        {
            get
            {
                if (keyDerivationParametersFactory == null)
                {
                    keyDerivationParametersFactory = new KeyDerivationParametersFactory();
                }

                return keyDerivationParametersFactory;
            }
        }

        /// <summary>
        /// Gets the service for signatures and encryption.
        /// </summary>
        public static ICryptographicEngine CryptographicEngine
        {
            get
            {
                if (cryptographicEngine == null)
                {
                    cryptographicEngine = new CryptographicEngine();
                }

                return cryptographicEngine;
            }
        }

        /// <summary>
        /// Gets the service for buffers.
        /// </summary>
        public static ICryptographicBuffer CryptographicBuffer
        {
            get
            {
                if (cryptographicBuffer == null)
                {
                    cryptographicBuffer = new CryptographicBuffer();
                }

                return cryptographicBuffer;
            }
        }
    }
}
