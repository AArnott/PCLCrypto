//-----------------------------------------------------------------------
// <copyright file="SymmetricKeyAlgorithmProviderFactory.cs" company="Andrew Arnott">
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

    /// <summary>
    /// WinRT implementation of the <see cref="ISymmetricKeyAlgorithmProviderFactory"/> interface.
    /// </summary>
    internal class SymmetricKeyAlgorithmProviderFactory : ISymmetricKeyAlgorithmProviderFactory
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyAlgorithmProviderFactory"/> class.
        /// </summary>
        public SymmetricKeyAlgorithmProviderFactory()
        {
        }

        /// <summary>
        /// A PCL-compatible enum describing symmetric algorithms.
        /// </summary>
        internal enum SymmetricAlgorithmTitle
        {
            /// <summary>
            /// The AES algorithm.
            /// </summary>
            Aes,

            /// <summary>
            /// The DES algorithm.
            /// </summary>
            Des,

            /// <summary>
            /// The TRIPLEDES algorithm.
            /// </summary>
            TripleDes,

            /// <summary>
            /// The RC2 algorithm.
            /// </summary>
            Rc2,

            /// <summary>
            /// The RC4 algorithm.
            /// </summary>
            Rc4,
        }

        /// <summary>
        /// A PCL-compatible enum describing symmetric cipher block modes.
        /// </summary>
        internal enum SymmetricAlgorithmMode
        {
            /// <summary>
            /// The CBC mode.
            /// </summary>
            Cbc,

            /// <summary>
            /// The ECB mode.
            /// </summary>
            Ecb,

            /// <summary>
            /// The CCM mode.
            /// </summary>
            Ccm,

            /// <summary>
            /// The GCM mode.
            /// </summary>
            Gcm,
        }

        /// <summary>
        /// A PCL-compatible enum describing cipher block padding options.
        /// </summary>
        internal enum SymmetricAlgorithmPadding
        {
            /// <summary>
            /// Use no padding at all.
            /// </summary>
            None,

            /// <summary>
            /// Use PKCS7 padding.
            /// </summary>
            PKCS7,
        }

        /// <inheritdoc />
        public ISymmetricKeyAlgorithmProvider OpenAlgorithm(SymmetricAlgorithm algorithm)
        {
            return new SymmetricKeyAlgorithmProvider(algorithm);
        }

        /// <summary>
        /// Returns a platform-specific algorithm that conforms to the prescribed platform-neutral algorithm.
        /// </summary>
        /// <param name="algorithm">The PCL algorithm.</param>
        /// <returns>
        /// The platform-specific algorithm.
        /// </returns>
        internal static SymmetricAlgorithmTitle GetTitle(SymmetricAlgorithm algorithm)
        {
            switch (algorithm)
            {
                case SymmetricAlgorithm.AesCbc:
                case SymmetricAlgorithm.AesCbcPkcs7:
                case SymmetricAlgorithm.AesCcm:
                case SymmetricAlgorithm.AesEcb:
                case SymmetricAlgorithm.AesEcbPkcs7:
                case SymmetricAlgorithm.AesGcm:
                    return SymmetricAlgorithmTitle.Aes;
                case SymmetricAlgorithm.DesCbc:
                case SymmetricAlgorithm.DesCbcPkcs7:
                case SymmetricAlgorithm.DesEcb:
                case SymmetricAlgorithm.DesEcbPkcs7:
                    return SymmetricAlgorithmTitle.Des;
                case SymmetricAlgorithm.Rc2Cbc:
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                case SymmetricAlgorithm.Rc2Ecb:
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                    return SymmetricAlgorithmTitle.Rc2;
                case SymmetricAlgorithm.Rc4:
                    return SymmetricAlgorithmTitle.Rc4;
                case SymmetricAlgorithm.TripleDesCbc:
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                case SymmetricAlgorithm.TripleDesEcb:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                    return SymmetricAlgorithmTitle.TripleDes;
                default:
                    throw new ArgumentException();
            }
        }

        /// <summary>
        /// Gets the name of the algorithm without including block mode or padding.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A non-empty string, such as "AES".</returns>
        internal static string GetTitleName(SymmetricAlgorithm algorithm)
        {
            return GetTitleName(GetTitle(algorithm));
        }

        /// <summary>
        /// Gets the name of the algorithm without including block mode or padding.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A non-empty string, such as "AES".</returns>
        internal static string GetTitleName(SymmetricAlgorithmTitle algorithm)
        {
            switch (algorithm)
            {
                case SymmetricKeyAlgorithmProviderFactory.SymmetricAlgorithmTitle.Aes:
                    return "AES";
                case SymmetricKeyAlgorithmProviderFactory.SymmetricAlgorithmTitle.Des:
                    return "DES";
                case SymmetricKeyAlgorithmProviderFactory.SymmetricAlgorithmTitle.Rc2:
                    return "RC2";
                case SymmetricKeyAlgorithmProviderFactory.SymmetricAlgorithmTitle.Rc4:
                    return "RC4";
                case SymmetricKeyAlgorithmProviderFactory.SymmetricAlgorithmTitle.TripleDes:
                    return "TRIPLEDES";
                default:
                    throw new ArgumentException();
            }
        }

        /// <summary>
        /// Gets the block mode for an algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The block mode.</returns>
        internal static SymmetricAlgorithmMode GetMode(SymmetricAlgorithm algorithm)
        {
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
                    return SymmetricAlgorithmMode.Cbc;
                case SymmetricAlgorithm.AesEcb:
                case SymmetricAlgorithm.AesEcbPkcs7:
                case SymmetricAlgorithm.DesEcb:
                case SymmetricAlgorithm.DesEcbPkcs7:
                case SymmetricAlgorithm.TripleDesEcb:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                case SymmetricAlgorithm.Rc2Ecb:
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                    return SymmetricAlgorithmMode.Ecb;
                case SymmetricAlgorithm.AesCcm:
                    return SymmetricAlgorithmMode.Ccm;
                case SymmetricAlgorithm.AesGcm:
                    return SymmetricAlgorithmMode.Gcm;
                default:
                    throw new ArgumentException();
            }
        }

        /// <summary>
        /// Gets the padding.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The padding.</returns>
        internal static SymmetricAlgorithmPadding GetPadding(SymmetricAlgorithm algorithm)
        {
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
                    return SymmetricAlgorithmPadding.None;
                case SymmetricAlgorithm.DesCbcPkcs7:
                case SymmetricAlgorithm.DesEcbPkcs7:
                case SymmetricAlgorithm.Rc2CbcPkcs7:
                case SymmetricAlgorithm.AesCbcPkcs7:
                case SymmetricAlgorithm.AesEcbPkcs7:
                case SymmetricAlgorithm.TripleDesCbcPkcs7:
                case SymmetricAlgorithm.Rc2EcbPkcs7:
                case SymmetricAlgorithm.TripleDesEcbPkcs7:
                    return SymmetricAlgorithmPadding.PKCS7;
                default:
                    throw new ArgumentException();
            }
        }
    }
}
