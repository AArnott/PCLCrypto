// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Collections.ObjectModel;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using static PInvoke.BCrypt;
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// A WinRT implementation of the <see cref="ISymmetricKeyAlgorithmProvider"/> interface.
    /// </summary>
    internal partial class SymmetricKeyAlgorithmProvider : ISymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// A lazy-initialized cache for the <see cref="LegalKeySizes"/> property.
        /// </summary>
        private IReadOnlyList<KeySizes> legalKeySizes;

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

            this.Algorithm = BCryptOpenAlgorithmProvider(GetAlgorithmName(name));
            try
            {
                BCryptSetProperty(this.Algorithm, PropertyNames.BCRYPT_CHAINING_MODE, GetChainingMode(mode));
            }
            catch (PInvoke.NTStatusException ex)
            {
                throw new ArgumentException(ex.Message, ex);
            }
        }

        /// <inheritdoc/>
        public int BlockLength
        {
            get { return BCryptGetProperty<int>(this.Algorithm, PropertyNames.BCRYPT_BLOCK_LENGTH); }
        }

        /// <inheritdoc/>
        public IReadOnlyList<KeySizes> LegalKeySizes
        {
            get
            {
                if (this.legalKeySizes == null)
                {
                    var keyLengths = BCryptGetProperty<BCRYPT_KEY_LENGTHS_STRUCT>(this.Algorithm, PropertyNames.BCRYPT_KEY_LENGTHS);
                    this.legalKeySizes = new ReadOnlyCollection<KeySizes>(
                        new[]
                        {
                            new KeySizes(keyLengths.MinLength, keyLengths.MaxLength, keyLengths.Increment),
                        });
                }

                return this.legalKeySizes;
            }
        }

        /// <summary>
        /// Gets the BCrypt algorithm.
        /// </summary>
        internal SafeAlgorithmHandle Algorithm { get; }

        /// <inheritdoc/>
        public ICryptographicKey CreateSymmetricKey(byte[] keyMaterial)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");

            return new SymmetricCryptographicKey(keyMaterial, this);
        }

        /// <summary>
        /// Disposes resources associated with this instance.
        /// </summary>
        public void Dispose()
        {
            this.Algorithm.Dispose();
        }

        /// <summary>
        /// Returns the string to pass to the platform APIs for a given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm desired.</param>
        /// <returns>The platform-specific string to pass to OpenAlgorithm.</returns>
        private static string GetAlgorithmName(SymmetricAlgorithmName algorithm)
        {
            switch (algorithm)
            {
                case SymmetricAlgorithmName.Aes:
                    return AlgorithmIdentifiers.BCRYPT_AES_ALGORITHM;
                case SymmetricAlgorithmName.Des:
                    return AlgorithmIdentifiers.BCRYPT_DES_ALGORITHM;
                case SymmetricAlgorithmName.TripleDes:
                    return AlgorithmIdentifiers.BCRYPT_3DES_ALGORITHM;
                case SymmetricAlgorithmName.Rc2:
                    return AlgorithmIdentifiers.BCRYPT_RC2_ALGORITHM;
                case SymmetricAlgorithmName.Rc4:
                    return AlgorithmIdentifiers.BCRYPT_RC4_ALGORITHM;
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Gets the BCrypt chaining mode to pass to set as the <see cref="PropertyNames.BCRYPT_CHAINING_MODE"/> property.
        /// </summary>
        /// <param name="mode">The block chaining mode.</param>
        /// <returns>The block chaining mode.</returns>
        private static string GetChainingMode(SymmetricAlgorithmMode mode)
        {
            switch (mode)
            {
                case SymmetricAlgorithmMode.Streaming: return ChainingModes.NotApplicable;
                case SymmetricAlgorithmMode.Cbc: return ChainingModes.Cbc;
                case SymmetricAlgorithmMode.Ecb: return ChainingModes.Ecb;
                case SymmetricAlgorithmMode.Ccm: return ChainingModes.Ccm;
                case SymmetricAlgorithmMode.Gcm: return ChainingModes.Gcm;
                default: throw new NotSupportedException();
            }
        }
    }
}
