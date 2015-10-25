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
    /// The WinRT implementation of the <see cref="IKeyDerivationAlgorithmProvider"/> interface.
    /// </summary>
    internal class KeyDerivationAlgorithmProvider : IKeyDerivationAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly KeyDerivationAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDerivationAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        internal KeyDerivationAlgorithmProvider(KeyDerivationAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public KeyDerivationAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public ICryptographicKey CreateKey(byte[] keyMaterial)
        {
            Requires.NotNull(keyMaterial, "keyMaterial");

            var platform = Platform.Core.KeyDerivationAlgorithmProvider.OpenAlgorithm(GetAlgorithmName(this.Algorithm));
            return new CryptographicKey(platform.CreateKey(keyMaterial.ToBuffer()), canExportPrivateKey: true);
        }

        /// <summary>
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        private static string GetAlgorithmName(KeyDerivationAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case KeyDerivationAlgorithm.Pbkdf2Md5:
                    return Platform.Core.KeyDerivationAlgorithmNames.Pbkdf2Md5;
                case KeyDerivationAlgorithm.Pbkdf2Sha1:
                    return Platform.Core.KeyDerivationAlgorithmNames.Pbkdf2Sha1;
                case KeyDerivationAlgorithm.Pbkdf2Sha256:
                    return Platform.Core.KeyDerivationAlgorithmNames.Pbkdf2Sha256;
                case KeyDerivationAlgorithm.Pbkdf2Sha384:
                    return Platform.Core.KeyDerivationAlgorithmNames.Pbkdf2Sha384;
                case KeyDerivationAlgorithm.Pbkdf2Sha512:
                    return Platform.Core.KeyDerivationAlgorithmNames.Pbkdf2Sha512;
                case KeyDerivationAlgorithm.Sp800108CtrHmacMd5:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp800108CtrHmacMd5;
                case KeyDerivationAlgorithm.Sp800108CtrHmacSha1:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp800108CtrHmacSha1;
                case KeyDerivationAlgorithm.Sp800108CtrHmacSha256:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp800108CtrHmacSha256;
                case KeyDerivationAlgorithm.Sp800108CtrHmacSha384:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp800108CtrHmacSha384;
                case KeyDerivationAlgorithm.Sp800108CtrHmacSha512:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp800108CtrHmacSha512;
                case KeyDerivationAlgorithm.Sp80056aConcatMd5:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp80056aConcatMd5;
                case KeyDerivationAlgorithm.Sp80056aConcatSha1:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp80056aConcatSha1;
                case KeyDerivationAlgorithm.Sp80056aConcatSha256:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp80056aConcatSha256;
                case KeyDerivationAlgorithm.Sp80056aConcatSha384:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp80056aConcatSha384;
                case KeyDerivationAlgorithm.Sp80056aConcatSha512:
                    return Platform.Core.KeyDerivationAlgorithmNames.Sp80056aConcatSha512;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
