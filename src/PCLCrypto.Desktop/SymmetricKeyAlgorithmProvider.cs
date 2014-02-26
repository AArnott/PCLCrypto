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
        /// <returns>The platform-specific algorithm.</returns>
        private static Platform.SymmetricAlgorithm GetAlgorithm(SymmetricAlgorithm algorithm)
        {
#if !SILVERLIGHT && !WINDOWS_PHONE
            Platform.SymmetricAlgorithm platform;
#endif

            switch (algorithm)
            {
#if !SILVERLIGHT && !WINDOWS_PHONE
                case SymmetricAlgorithm.AesCbc:
                    platform = Platform.SymmetricAlgorithm.Create("AES");
                    platform.Mode = Platform.CipherMode.CBC;
                    platform.Padding = Platform.PaddingMode.None;
                    return platform;
                case SymmetricAlgorithm.AesCbcPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("AES");
                    platform.Mode = Platform.CipherMode.CBC;
                    platform.Padding = Platform.PaddingMode.PKCS7;
                    return platform;
                case SymmetricAlgorithm.AesEcb:
                    platform = Platform.SymmetricAlgorithm.Create("AES");
                    platform.Mode = Platform.CipherMode.ECB;
                    platform.Padding = Platform.PaddingMode.None;
                    return platform;
                case SymmetricAlgorithm.AesEcbPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("AES");
                    platform.Mode = Platform.CipherMode.ECB;
                    platform.Padding = Platform.PaddingMode.PKCS7;
                    return platform;
                case SymmetricAlgorithm.DesCbc:
                    platform = Platform.SymmetricAlgorithm.Create("DES");
                    platform.Mode = Platform.CipherMode.CBC;
                    platform.Padding = Platform.PaddingMode.None;
                    return platform;
                case SymmetricAlgorithm.DesCbcPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("DES");
                    platform.Mode = Platform.CipherMode.CBC;
                    platform.Padding = Platform.PaddingMode.PKCS7;
                    return platform;
                case SymmetricAlgorithm.DesEcb:
                    platform = Platform.SymmetricAlgorithm.Create("DES");
                    platform.Mode = Platform.CipherMode.ECB;
                    platform.Padding = Platform.PaddingMode.None;
                    return platform;
                case SymmetricAlgorithm.DesEcbPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("DES");
                    platform.Mode = Platform.CipherMode.ECB;
                    platform.Padding = Platform.PaddingMode.PKCS7;
                    return platform;
                case SymmetricAlgorithm.Rc2Cbc:
                    platform = Platform.SymmetricAlgorithm.Create("RC2");
                    platform.Mode = Platform.CipherMode.CBC;
                    platform.Padding = Platform.PaddingMode.None;
                    return platform;
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("RC2");
                    platform.Mode = Platform.CipherMode.CBC;
                    platform.Padding = Platform.PaddingMode.PKCS7;
                    return platform;
                case SymmetricAlgorithm.Rc2Ecb:
                    platform = Platform.SymmetricAlgorithm.Create("RC2");
                    platform.Mode = Platform.CipherMode.ECB;
                    platform.Padding = Platform.PaddingMode.None;
                    return platform;
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("RC2");
                    platform.Mode = Platform.CipherMode.ECB;
                    platform.Padding = Platform.PaddingMode.PKCS7;
                    return platform;
                case SymmetricAlgorithm.Rc4:
                    platform = Platform.SymmetricAlgorithm.Create("RC4");
                    return platform;
                case SymmetricAlgorithm.TripleDesCbc:
                    platform = Platform.SymmetricAlgorithm.Create("TRIPLEDES");
                    platform.Mode = Platform.CipherMode.CBC;
                    platform.Padding = Platform.PaddingMode.None;
                    return platform;
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("TRIPLEDES");
                    platform.Mode = Platform.CipherMode.CBC;
                    platform.Padding = Platform.PaddingMode.PKCS7;
                    return platform;
                case SymmetricAlgorithm.TripleDesEcb:
                    platform = Platform.SymmetricAlgorithm.Create("TRIPLEDES");
                    platform.Mode = Platform.CipherMode.ECB;
                    platform.Padding = Platform.PaddingMode.None;
                    return platform;
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                    platform = Platform.SymmetricAlgorithm.Create("TRIPLEDES");
                    platform.Mode = Platform.CipherMode.ECB;
                    platform.Padding = Platform.PaddingMode.PKCS7;
                    return platform;
#endif
                default:
                    throw new NotSupportedException();
            }
        }
    }
}
