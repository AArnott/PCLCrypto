// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Security.Cryptography;
    using Microsoft;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET Framework implementation of the <see cref="ICryptographicKey"/> interface
    /// for use with <see cref="KeyDerivationAlgorithmProvider"/>.
    /// </summary>
    internal class KeyDerivationCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The algorithm to use when deriving a cryptographic key.
        /// </summary>
        private readonly KeyDerivationAlgorithm algorithm;

        /// <summary>
        /// The key material.
        /// </summary>
        private readonly byte[] key;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDerivationCryptographicKey"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm to use when deriving a cryptographic key.</param>
        /// <param name="key">The key.</param>
        internal KeyDerivationCryptographicKey(KeyDerivationAlgorithm algorithm, byte[] key)
        {
            Requires.NotNull(key, nameof(key));
            this.algorithm = algorithm;
            this.key = key;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { return this.key.Length * 8; }
        }

        /// <summary>
        /// Gets the key material.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        internal byte[] Key
        {
            get { return this.key; }
        }

        /// <summary>
        /// Gets the algorithm to use when deriving a cryptographic key.
        /// </summary>
        internal KeyDerivationAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            throw new NotImplementedException();
        }

        /// <inheritdoc />
        protected internal override byte[] DeriveKeyMaterial(IKeyDerivationParameters parameters, int desiredKeySize)
        {
            // Right now we're assuming that KdfGenericBinary is directly usable as a salt
            // in RFC2898. When our KeyDerivationParametersFactory class supports
            // more parameter types than just BuildForPbkdf2, we might need to adjust this code
            // to handle each type of parameter.
            byte[] salt = parameters.KdfGenericBinary;
#pragma warning disable CA5379 // Do Not Use Weak Key Derivation Function Algorithm
            switch (this.Algorithm)
            {
                case KeyDerivationAlgorithm.Pbkdf2Sha1:
                    using (var deriveBytes = new Platform.Rfc2898DeriveBytes(this.Key, salt, parameters.IterationCount))
                    {
                        return deriveBytes.GetBytes(desiredKeySize);
                    }

                default:
#if NETSTANDARD2_0
                    throw new NotImplementedByReferenceAssemblyException();
#else
                    using (var deriveBytes = new Platform.Rfc2898DeriveBytes(this.Key, salt, parameters.IterationCount, GetHashAlgorithm(this.Algorithm)))
                    {
                        return deriveBytes.GetBytes(desiredKeySize);
                    }
#endif
            }
#pragma warning restore CA5379 // Do Not Use Weak Key Derivation Function Algorithm
        }

        private static HashAlgorithmName GetHashAlgorithm(KeyDerivationAlgorithm keyDerivationAlgorithm)
        {
            return keyDerivationAlgorithm switch
            {
                KeyDerivationAlgorithm.Pbkdf2Md5 => HashAlgorithmName.MD5,
                KeyDerivationAlgorithm.Pbkdf2Sha1 => HashAlgorithmName.SHA1,
                KeyDerivationAlgorithm.Pbkdf2Sha256 => HashAlgorithmName.SHA256,
                KeyDerivationAlgorithm.Pbkdf2Sha384 => HashAlgorithmName.SHA384,
                KeyDerivationAlgorithm.Pbkdf2Sha512 => HashAlgorithmName.SHA512,
                _ => throw new NotSupportedException($"{keyDerivationAlgorithm} is not supported on this platform."),
            };
        }
    }
}
