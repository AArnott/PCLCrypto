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
        /// The flags to use during encryption.
        /// </summary>
        private readonly BCryptEncryptFlags flags;

        /// <summary>
        /// The IV returned from the last cryptographic operation, which may serve
        /// as input into the next if the caller omits the IV.
        /// </summary>
        /// <seealso cref="platformKey"/>
        private byte[] iv;

        /// <summary>
        /// The key that may carry state from a prior crypto operation.
        /// </summary>
        /// <seealso cref="iv"/>
        private SafeKeyHandle platformKey;

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

            if (this.Padding == SymmetricAlgorithmPadding.PKCS7)
            {
                this.flags |= BCryptEncryptFlags.BCRYPT_BLOCK_PADDING;
            }
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
            this.platformKey?.Dispose();
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] plaintext, byte[] iv)
        {
            Verify.Operation(!this.Mode.IsAuthenticated(), "Cannot encrypt using this function when using an authenticated block chaining mode.");

            var key = this.GetInitializedKey(iv);
            switch (this.Padding)
            {
                case SymmetricAlgorithmPadding.None:
                    Requires.Argument(this.IsValidInputSize(plaintext.Length), nameof(plaintext), "Length is not a non-zero multiple of block size and no padding is selected.");
                    break;
                case SymmetricAlgorithmPadding.PKCS7:
                    break;
                case SymmetricAlgorithmPadding.Zeros:
                    // We have to implement this padding ourselves.
                    if (plaintext.Length == 0)
                    {
                        return plaintext;
                    }

                    CryptoUtilities.ApplyZeroPadding(ref plaintext, this.symmetricAlgorithmProvider.BlockLength);
                    break;
                default:
                    throw new NotSupportedException();
            }

            // We use the IV if the caller passes it in, or use
            // the resulting IV of the last cipher operation if the caller
            // did not specify an IV.
            // Copy the IV because the native code changes it, and
            // our contract with the caller is that we don't.
            this.iv = CopyBufferOrNull(iv) ?? this.iv;

            byte[] cipherText = BCryptEncrypt(
                key,
                plaintext,
                IntPtr.Zero,
                this.iv,
                this.flags).ToArray();
            return cipherText;
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] ciphertext, byte[] iv)
        {
            Requires.NotNull(ciphertext, nameof(ciphertext));
            Requires.Argument(this.IsValidInputSize(ciphertext.Length), nameof(ciphertext), "Length does not a multiple of block size and no padding is selected.");
            Verify.Operation(!this.Mode.IsAuthenticated(), "Cannot encrypt using this function when using an authenticated block chaining mode.");

            var key = this.GetInitializedKey(iv);
            switch (this.Padding)
            {
                case SymmetricAlgorithmPadding.PKCS7:
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

            // We use the IV if the caller passes it in, or use
            // the resulting IV of the last cipher operation if the caller
            // did not specify an IV.
            // Copy the IV because the native code changes it, and
            // our contract with the caller is that we don't.
            this.iv = CopyBufferOrNull(iv) ?? this.iv;

            byte[] plainText = BCryptDecrypt(
                key,
                ciphertext,
                IntPtr.Zero,
                this.iv,
                this.flags).ToArray();
            return plainText;
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateEncryptor(byte[] iv)
        {
            return new BufferingCryptoTransform(input => this.Encrypt(input, iv));
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateDecryptor(byte[] iv)
        {
            return new BufferingCryptoTransform(input => this.Decrypt(input, iv));
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

        private SafeKeyHandle GetInitializedKey(byte[] iv)
        {
            if (this.platformKey == null || !this.CanStreamAcrossTopLevelCipherOperations || iv != null)
            {
                this.platformKey?.Dispose();
                try
                {
                    this.platformKey = BCryptGenerateSymmetricKey(this.symmetricAlgorithmProvider.Algorithm, this.keyMaterial);
                }
                catch (Win32Exception ex)
                {
                    throw new ArgumentException(ex.Message, ex);
                }
            }

            return this.platformKey;
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

        private SafeKeyHandle CreateKey()
        {
            return BCryptImportKey(
                this.symmetricAlgorithmProvider.Algorithm,
                SymmetricKeyBlobTypes.BCRYPT_KEY_DATA_BLOB,
                this.keyMaterial);
        }
    }
}
