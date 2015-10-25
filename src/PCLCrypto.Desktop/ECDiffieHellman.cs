// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET implementation of the <see cref="IECDiffieHellman"/> interface.
    /// </summary>
    internal class ECDiffieHellman : IECDiffieHellman
    {
        /// <summary>
        /// The .NET algorithm backing this instance.
        /// </summary>
        private readonly Platform.ECDiffieHellman platformAlgorithm;

        private ECDiffieHellmanPublicKey publicKey;

        /// <summary>
        /// Initializes a new instance of the <see cref="ECDiffieHellman"/> class.
        /// </summary>
        /// <param name="platformAlgorithm">The .NET algorithm backing this instance.</param>
        internal ECDiffieHellman(Platform.ECDiffieHellman platformAlgorithm)
        {
            Requires.NotNull(platformAlgorithm, nameof(platformAlgorithm));
            this.platformAlgorithm = platformAlgorithm;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get
            {
                return this.platformAlgorithm.KeySize;
            }

            set
            {
                this.platformAlgorithm.KeySize = value;
                this.publicKey = null;
            }
        }

        /// <inheritdoc />
        public IECDiffieHellmanPublicKey PublicKey
        {
            get
            {
                if (this.publicKey == null)
                {
                    this.publicKey = new ECDiffieHellmanPublicKey(this.platformAlgorithm.PublicKey);
                }

                return this.publicKey;
            }
        }

        /// <inheritdoc />
        public byte[] DeriveKeyMaterial(IECDiffieHellmanPublicKey otherParty)
        {
            Requires.NotNull(otherParty, nameof(otherParty));

            var other = (ECDiffieHellmanPublicKey)otherParty;
            return this.platformAlgorithm.DeriveKeyMaterial(other.PlatformPublicKey);
        }

        /// <summary>
        /// Disposes of managed resources associated with this object.
        /// </summary>
        public void Dispose()
        {
            this.platformAlgorithm.Dispose();
        }
    }
}
