//-----------------------------------------------------------------------
// <copyright file="SymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
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
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET Framework implementation of the <see cref="ISymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal class SymmetricKeyAlgorithmProvider : ISymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly SymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public SymmetricKeyAlgorithmProvider(SymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc/>
        public SymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc/>
        public int BlockLength
        {
            get
            {
                using (var platform = GetAlgorithm(this.algorithm))
                {
                    return platform.BlockSize / 8;
                }
            }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateSymmetricKey(byte[] keyMaterial)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");

            var platform = GetAlgorithm(this.algorithm);
            try
            {
                platform.Key = keyMaterial;
            }
            catch (Platform.CryptographicException ex)
            {
#if SILVERLIGHT
                throw new ArgumentException(ex.Message, ex);
#else
                throw new ArgumentException(ex.Message, "keyMaterial", ex);
#endif
            }

            return new SymmetricCryptographicKey(platform);
        }

        /// <summary>
        /// Returns a platform-specific algorithm that conforms to the prescribed platform-neutral algorithm.
        /// </summary>
        /// <param name="algorithm">The PCL algorithm.</param>
        /// <returns>
        /// The platform-specific algorithm.
        /// </returns>
        /// <exception cref="System.NotSupportedException">
        /// </exception>
        private static Platform.SymmetricAlgorithm GetAlgorithm(SymmetricAlgorithm algorithm)
        {
#if SILVERLIGHT
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbcPkcs7:
                    return new Platform.AesManaged();
                default:
                    throw new NotSupportedException();
            }
#else
            Platform.SymmetricAlgorithm platform;

            // Algorithm
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbc:
                case SymmetricAlgorithm.AesCbcPkcs7:
                case SymmetricAlgorithm.AesCcm:
                case SymmetricAlgorithm.AesEcb:
                case SymmetricAlgorithm.AesEcbPkcs7:
                case SymmetricAlgorithm.AesGcm:
                    platform = Platform.SymmetricAlgorithm.Create("AES");
                    break;
                case SymmetricAlgorithm.DesCbc:
                case SymmetricAlgorithm.DesCbcPkcs7:
                case SymmetricAlgorithm.DesEcb:
                case SymmetricAlgorithm.DesEcbPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("DES");
                    break;
                case SymmetricAlgorithm.Rc2Cbc:
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                case SymmetricAlgorithm.Rc2Ecb:
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("RC2");
                    break;
                case SymmetricAlgorithm.Rc4:
                    platform = Platform.SymmetricAlgorithm.Create("RC4");
                    break;
                case SymmetricAlgorithm.TripleDesCbc:
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                case SymmetricAlgorithm.TripleDesEcb:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("TRIPLEDES");
                    break;
                default:
                    throw new NotSupportedException();
            }

            // Mode
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbc:
                case SymmetricAlgorithm.AesCbcPkcs7:
                case SymmetricAlgorithm.Rc2Cbc:
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                case SymmetricAlgorithm.DesCbc:
                case SymmetricAlgorithm.DesCbcPkcs7:
                case SymmetricAlgorithm.TripleDesCbc:
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                    platform.Mode = Platform.CipherMode.CBC;
                    break;
                case SymmetricAlgorithm.AesEcb:
                case SymmetricAlgorithm.AesEcbPkcs7:
                case SymmetricAlgorithm.DesEcb:
                case SymmetricAlgorithm.DesEcbPkcs7:
                case SymmetricAlgorithm.TripleDesEcb:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                case SymmetricAlgorithm.Rc2Ecb:
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                    platform.Mode = Platform.CipherMode.ECB;
                    break;
                case SymmetricAlgorithm.AesCcm:
                case SymmetricAlgorithm.AesGcm:
                    throw new NotSupportedException();
                default:
                    break;
            }

            // Padding
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbc:
                case SymmetricAlgorithm.AesEcb:
                case SymmetricAlgorithm.DesCbc:
                case SymmetricAlgorithm.DesEcb:
                case SymmetricAlgorithm.Rc2Ecb:
                case SymmetricAlgorithm.TripleDesCbc:
                case SymmetricAlgorithm.TripleDesEcb:
                case SymmetricAlgorithm.Rc2Cbc:
                    platform.Padding = Platform.PaddingMode.None;
                    break;
                case SymmetricAlgorithm.DesCbcPkcs7:
                case SymmetricAlgorithm.DesEcbPkcs7:
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                case SymmetricAlgorithm.AesCbcPkcs7:
                case SymmetricAlgorithm.AesEcbPkcs7:
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                    platform.Padding = Platform.PaddingMode.PKCS7;
                    break;
                default:
                    break;
            }

            return platform;
#endif
        }
    }
}
