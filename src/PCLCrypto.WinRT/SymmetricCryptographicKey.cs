// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading.Tasks;
    using PInvoke;
    using Validation;
    using static PInvoke.BCrypt;

    /// <summary>
    /// The WinRT implementation of the <see cref="ICryptographicKey"/> interface.
    /// </summary>
    internal partial class SymmetricCryptographicKey : CryptographicKey, ICryptographicKey
    {
        /// <summary>
        /// The symmetric key material.
        /// </summary>
        private readonly byte[] keyMaterial;

        /// <summary>
        /// The symmetric algorithm used when creating this key, when applicable.
        /// </summary>
        private readonly SymmetricKeyAlgorithmProvider symmetricAlgorithmProvider;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricCryptographicKey" /> class.
        /// </summary>
        /// <param name="keyMaterial">The symmetric key.</param>
        /// <param name="symmetricAlgorithmProvider">The symmetric algorithm of the provider creating this key.</param>
        internal SymmetricCryptographicKey(byte[] keyMaterial, SymmetricKeyAlgorithmProvider symmetricAlgorithmProvider)
        {
            Requires.NotNullOrEmpty(keyMaterial, nameof(keyMaterial));
            Requires.NotNull(symmetricAlgorithmProvider, nameof(symmetricAlgorithmProvider));

            this.symmetricAlgorithmProvider = symmetricAlgorithmProvider;

            // Copy the key material so our caller can reuse their buffer.
            this.keyMaterial = new byte[keyMaterial.Length];
            Array.Copy(keyMaterial, this.keyMaterial, keyMaterial.Length);

            this.Name = symmetricAlgorithmProvider.Name;
            this.Mode = symmetricAlgorithmProvider.Mode;
            this.Padding = symmetricAlgorithmProvider.Padding;
        }

        /// <inheritdoc />
        public int KeySize => this.keyMaterial.Length * 8;

        /// <summary>
        /// Gets the symmetric algorithm provider that created this key, if applicable.
        /// </summary>
        internal SymmetricKeyAlgorithmProvider SymmetricAlgorithmProvider => this.symmetricAlgorithmProvider;

        /// <summary>
        /// Gets the key material buffer.
        /// </summary>
        internal byte[] KeyMaterial => this.keyMaterial;

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Disposes of managed resources associated with this object.
        /// </summary>
        public void Dispose()
        {
        }

        /// <inheritdoc />
        internal override byte[] Encrypt(byte[] plaintext, byte[] iv)
        {
            using (var k = new ProviderAndKey(this))
            {
                switch (this.Padding)
                {
                    case SymmetricAlgorithmPadding.None:
                        Requires.Argument(this.IsValidInputSize(plaintext.Length), nameof(plaintext), "Length is not a non-zero multiple of block size and no padding is selected.");
                        break;
                    case SymmetricAlgorithmPadding.PKCS7:
                        k.Flags |= BCryptEncryptFlags.BCRYPT_BLOCK_PADDING;
                        break;
                    case SymmetricAlgorithmPadding.Zeros:
                        // We have to implement this padding ourselves.
                        if (plaintext.Length == 0)
                        {
                            return plaintext;
                        }

                        this.GrowToMultipleOfBlockSize(ref plaintext);
                        break;
                    default:
                        throw new NotSupportedException();
                }

                // Copy the IV because the native code changes it, and
                // our contract with the caller is that we don't.
                byte[] cipherText = BCryptEncrypt(
                    k.Key,
                    plaintext,
                    IntPtr.Zero,
                    CopyBufferOrNull(iv), // shield our caller from mutations
                    k.Flags);
                return cipherText;
            }
        }

        /// <inheritdoc />
        internal override byte[] Decrypt(byte[] ciphertext, byte[] iv)
        {
            Requires.NotNull(ciphertext, nameof(ciphertext));

            Requires.Argument(this.IsValidInputSize(ciphertext.Length), nameof(ciphertext), "Length does not a multiple of block size and no padding is selected.");
            using (var k = new ProviderAndKey(this))
            {
                switch (this.Padding)
                {
                    case SymmetricAlgorithmPadding.PKCS7:
                        k.Flags |= BCryptEncryptFlags.BCRYPT_BLOCK_PADDING;
                        break;
                    case SymmetricAlgorithmPadding.None:
                    case SymmetricAlgorithmPadding.Zeros:
                        if (ciphertext.Length == 0)
                        {
                            return ciphertext;
                        }

                        break;
                    default:
                        throw new NotSupportedException();
                }

                byte[] plainText = BCryptDecrypt(
                    k.Key,
                    ciphertext,
                    IntPtr.Zero,
                    CopyBufferOrNull(iv), // shield our caller from mutations
                    k.Flags);
                return plainText;
            }
        }

        /// <summary>
        /// Gets the BCrypt algorithm identifier to pass to <see cref="BCryptOpenAlgorithmProvider(string, string, BCryptOpenAlgorithmProviderFlags)"/>.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The algorithm identifier.</returns>
        private static string GetAlgorithmIdentifier(SymmetricAlgorithmName algorithm)
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
        /// Gets the BCrypt chaining mode to pass to set as the <see cref="PropertyNames.ChainingMode"/> property.
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

        private static byte[] CopyBufferOrNull(byte[] buffer)
        {
            if (buffer == null)
            {
                return null;
            }

            var copy = new byte[buffer.Length];
            Array.Copy(buffer, copy, buffer.Length);
            return copy;
        }

        /// <summary>
        /// Checks whether the given length is a valid one for an input buffer to the symmetric algorithm.
        /// </summary>
        /// <param name="lengthInBytes">The length of the input buffer in bytes.</param>
        /// <returns>
        ///   <c>true</c> if the size is allowed; <c>false</c> otherwise.
        /// </returns>
        private bool IsValidInputSize(int lengthInBytes)
        {
            return lengthInBytes % this.SymmetricAlgorithmProvider.BlockLength == 0;
        }

        private void GrowToMultipleOfBlockSize(ref byte[] buffer)
        {
            Requires.NotNull(buffer, nameof(buffer));

            int blockLength = this.SymmetricAlgorithmProvider.BlockLength;
            int bytesBeyondLastBlockLength = buffer.Length % blockLength;
            if (bytesBeyondLastBlockLength > 0)
            {
                int growBy = blockLength - bytesBeyondLastBlockLength;
                Array.Resize(ref buffer, buffer.Length + growBy);
            }
        }

        private SafeKeyHandle CreateKey()
        {
            return BCryptImportKey(
                this.symmetricAlgorithmProvider.Algorithm,
                SymmetricKeyBlobTypes.BCRYPT_KEY_DATA_BLOB,
                this.keyMaterial);
        }

        private class ProviderAndKey : IDisposable
        {
            public ProviderAndKey(SymmetricCryptographicKey key)
            {
                this.Provider = null;
                this.Key = null;
                try
                {
                    this.Provider = BCryptOpenAlgorithmProvider(GetAlgorithmIdentifier(key.Name));
                    BCryptSetProperty(this.Provider, PropertyNames.ChainingMode, GetChainingMode(key.Mode));
                    this.Key = BCryptGenerateSymmetricKey(this.Provider, key.keyMaterial);
                }
                catch
                {
                    this.Key?.Dispose();
                    this.Provider?.Dispose();
                    throw;
                }

                this.Flags = BCryptEncryptFlags.None;
            }

            public SafeAlgorithmHandle Provider { get; private set; }

            public SafeKeyHandle Key { get; private set; }

            public BCryptEncryptFlags Flags { get; set; }

            public void Dispose()
            {
                this.Key?.Dispose();
                this.Provider?.Dispose();
            }
        }
    }
}
