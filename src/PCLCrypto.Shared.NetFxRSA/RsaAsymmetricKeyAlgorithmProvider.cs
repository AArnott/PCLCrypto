//-----------------------------------------------------------------------
// <copyright file="RsaAsymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
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
#if DESKTOP
    using Mono.Security.Cryptography;
#endif
    using PCLCrypto.Formatters;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// The .NET Framework implementation of RSA.
    /// </summary>
    internal class RsaAsymmetricKeyAlgorithmProvider : IAsymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly AsymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="RsaAsymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        public RsaAsymmetricKeyAlgorithmProvider(AsymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc/>
        public AsymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc/>
        public ICryptographicKey CreateKeyPair(int keySize)
        {
            Requires.Range(keySize > 0, "keySize");

            var rsa = new Platform.RSACryptoServiceProvider(keySize);
            return new RsaCryptographicKey(rsa, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportKeyPair(byte[] keyBlob, CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            var parameters = KeyFormatter.GetFormatter(blobType).Read(keyBlob);
            Platform.RSA rsa;
            if (CapiKeyFormatter.IsCapiCompatible(parameters))
            {
                rsa = new Platform.RSACryptoServiceProvider();
            }
            else
            {
#if DESKTOP
                rsa = new RSAManaged();
#else
                CapiKeyFormatter.VerifyCapiCompatibleParameters(parameters);
                throw new NotSupportedException();
#endif
            }

            rsa.ImportParameters(KeyFormatter.ToPlatformParameters(parameters));
            return new RsaCryptographicKey(rsa, this.algorithm);
        }

        /// <inheritdoc/>
        public ICryptographicKey ImportPublicKey(byte[] keyBlob, CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            Requires.NotNull(keyBlob, "keyBlob");

            var rsa = new Platform.RSACryptoServiceProvider();
            rsa.ImportParameters(KeyFormatter.ToPlatformParameters(KeyFormatter.GetFormatter(blobType).Read(keyBlob)));
            return new RsaCryptographicKey(rsa, this.algorithm);
        }
    }
}
