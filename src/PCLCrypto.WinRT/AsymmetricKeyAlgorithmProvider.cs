//-----------------------------------------------------------------------
// <copyright file="AsymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
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
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// WinRT implementation of the <see cref="IAsymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    public class AsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The WinRT platform implementation.
        /// </summary>
        private readonly Platform.AsymmetricKeyAlgorithmProvider platform;

        /// <summary>
        /// Initializes a new instance of the <see cref="AsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public AsymmetricKeyAlgorithmProvider(string algorithm)
        {
            this.platform = Platform.AsymmetricKeyAlgorithmProvider.OpenAlgorithm(algorithm);
        }

        /// <inheritdoc/>
        public string AlgorithmName
        {
            get { return this.platform.AlgorithmName; }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyPair)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType)
        {
            throw new NotImplementedException();
        }
    }
}
