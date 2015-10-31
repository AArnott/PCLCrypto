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
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// A WinRT implementation of the <see cref="ISymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal partial class SymmetricKeyAlgorithmProvider : ISymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The WinRT platform implementation.
        /// </summary>
        private readonly Platform.SymmetricKeyAlgorithmProvider platform;

        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly SymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="name">The name of the base algorithm to use.</param>
        /// <param name="mode">The algorithm's mode (i.e. streaming or some block mode).</param>
        /// <param name="padding">The padding to use.</param>
        public SymmetricKeyAlgorithmProvider(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding)
        {
            this.Name = name;
            this.Mode = mode;
            this.Padding = padding;

            if (!SymmetricAlgorithmExtensions.TryAssemblyAlgorithm(name, mode, padding, out this.algorithm))
            {
                throw new NotSupportedException();
            }

            this.platform = Platform.SymmetricKeyAlgorithmProvider.OpenAlgorithm(GetAlgorithmName(this.Algorithm));
        }

        /// <summary>
        /// Gets the algorithm supported by this provider.
        /// </summary>
        public SymmetricAlgorithm Algorithm => this.algorithm;

        /// <inheritdoc/>
        public int BlockLength
        {
            get { return (int)this.platform.BlockLength; }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateSymmetricKey(byte[] keyMaterial)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");

            var key = this.platform.CreateSymmetricKey(keyMaterial.ToBuffer());
            return new CryptographicKey(key, this, canExportPrivateKey: true);
        }

        /// <summary>
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        private static string GetAlgorithmName(SymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbc:
                    return Platform.SymmetricAlgorithmNames.AesCbc;
                case SymmetricAlgorithm.AesCbcPkcs7:
                    return Platform.SymmetricAlgorithmNames.AesCbcPkcs7;
                case SymmetricAlgorithm.AesCcm:
                    return Platform.SymmetricAlgorithmNames.AesCcm;
                case SymmetricAlgorithm.AesEcb:
                    return Platform.SymmetricAlgorithmNames.AesEcb;
                case SymmetricAlgorithm.AesEcbPkcs7:
                    return Platform.SymmetricAlgorithmNames.AesEcbPkcs7;
                case SymmetricAlgorithm.AesGcm:
                    return Platform.SymmetricAlgorithmNames.AesGcm;
                case SymmetricAlgorithm.DesCbc:
                    return Platform.SymmetricAlgorithmNames.DesCbc;
                case SymmetricAlgorithm.DesCbcPkcs7:
                    return Platform.SymmetricAlgorithmNames.DesCbcPkcs7;
                case SymmetricAlgorithm.DesEcb:
                    return Platform.SymmetricAlgorithmNames.DesEcb;
                case SymmetricAlgorithm.DesEcbPkcs7:
                    return Platform.SymmetricAlgorithmNames.DesEcbPkcs7;
                case SymmetricAlgorithm.Rc2Cbc:
                    return Platform.SymmetricAlgorithmNames.Rc2Cbc;
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                    return Platform.SymmetricAlgorithmNames.Rc2CbcPkcs7;
                case SymmetricAlgorithm.Rc2Ecb:
                    return Platform.SymmetricAlgorithmNames.Rc2Ecb;
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                    return Platform.SymmetricAlgorithmNames.Rc2EcbPkcs7;
                case SymmetricAlgorithm.Rc4:
                    return Platform.SymmetricAlgorithmNames.Rc4;
                case SymmetricAlgorithm.TripleDesCbc:
                    return Platform.SymmetricAlgorithmNames.TripleDesCbc;
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                    return Platform.SymmetricAlgorithmNames.TripleDesCbcPkcs7;
                case SymmetricAlgorithm.TripleDesEcb:
                    return Platform.SymmetricAlgorithmNames.TripleDesEcb;
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                    return Platform.SymmetricAlgorithmNames.TripleDesEcbPkcs7;
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
