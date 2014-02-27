//-----------------------------------------------------------------------
// <copyright file="MacAlgorithmProvider.cs" company="Andrew Arnott">
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
    using Platform = System.Security.Cryptography;

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
        /// Initializes a new instance of the <see cref="MacAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal MacAlgorithmProvider(MacAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public MacAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public int MacLength
        {
            get
            {
                using (var algorithm = GetAlgorithmName(this.Algorithm))
                {
                    return algorithm.HashSize / 8;
                }
            }
        }

        /// <inheritdoc />
        public ICryptographicHash CreateHash(byte[] keyMaterial)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public ICryptographicKey CreateKey(byte[] keyMaterial)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        private static Platform.KeyedHashAlgorithm GetAlgorithmName(MacAlgorithm algorithm)
        {
            switch (algorithm)
            {
#if !SILVERLIGHT && !WINDOWS_PHONE
                case MacAlgorithm.AesCmac:
                    return Platform.KeyedHashAlgorithm.Create("AesCmac");
                case MacAlgorithm.HmacMd5:
                    return Platform.KeyedHashAlgorithm.Create("HmacMd5");
                case MacAlgorithm.HmacSha1:
                    return Platform.KeyedHashAlgorithm.Create("HmacSha1");
                case MacAlgorithm.HmacSha256:
                    return Platform.KeyedHashAlgorithm.Create("HmacSha256");
                case MacAlgorithm.HmacSha384:
                    return Platform.KeyedHashAlgorithm.Create("HmacSha384");
                case MacAlgorithm.HmacSha512:
                    return Platform.KeyedHashAlgorithm.Create("HmacSha512");
#endif
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
