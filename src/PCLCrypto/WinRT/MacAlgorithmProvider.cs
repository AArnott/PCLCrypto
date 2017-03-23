// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using Platform = Windows.Security.Cryptography;

    /// <summary>
    /// The WinRT implementation of the <see cref="IMacAlgorithmProvider"/> interface.
    /// </summary>
    internal class MacAlgorithmProvider : IMacAlgorithmProvider
    {
        /// <summary>
        /// The algorithm of this instance.
        /// </summary>
        private readonly MacAlgorithm algorithm;

        /// <summary>
        /// The platform implementation of this algorithm.
        /// </summary>
        private readonly Platform.Core.MacAlgorithmProvider platform;

        /// <summary>
        /// Initializes a new instance of the <see cref="MacAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal MacAlgorithmProvider(MacAlgorithm algorithm)
        {
            this.algorithm = algorithm;
            this.platform = Platform.Core.MacAlgorithmProvider.OpenAlgorithm(GetAlgorithmName(algorithm));
        }

        /// <inheritdoc />
        public MacAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public int MacLength
        {
            get { return (int)this.platform.MacLength; }
        }

        /// <inheritdoc />
        public CryptographicHash CreateHash(byte[] keyMaterial)
        {
            Requires.NotNull(keyMaterial, "keyMaterial");
            return new WinRTCryptographicHash(this.platform.CreateHash(keyMaterial.ToBuffer()));
        }

        /// <inheritdoc />
        public ICryptographicKey CreateKey(byte[] keyMaterial)
        {
            Requires.NotNull(keyMaterial, "keyMaterial");
            return new WinRTCryptographicKey(this.platform.CreateKey(keyMaterial.ToBuffer()));
        }

        /// <summary>
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        private static string GetAlgorithmName(MacAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case MacAlgorithm.AesCmac:
                    return Platform.Core.MacAlgorithmNames.AesCmac;
                case MacAlgorithm.HmacMd5:
                    return Platform.Core.MacAlgorithmNames.HmacMd5;
                case MacAlgorithm.HmacSha1:
                    return Platform.Core.MacAlgorithmNames.HmacSha1;
                case MacAlgorithm.HmacSha256:
                    return Platform.Core.MacAlgorithmNames.HmacSha256;
                case MacAlgorithm.HmacSha384:
                    return Platform.Core.MacAlgorithmNames.HmacSha384;
                case MacAlgorithm.HmacSha512:
                    return Platform.Core.MacAlgorithmNames.HmacSha512;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
