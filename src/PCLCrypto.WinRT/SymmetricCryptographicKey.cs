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
    internal partial class SymmetricCryptographicKey : BCryptCryptographicKeyBase, ICryptographicKey
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
        /// <seealso cref="encryptorKey"/>
        private byte[] encryptorIv;

        /// <summary>
        /// The IV returned from the last cryptographic operation, which may serve
        /// as input into the next if the caller omits the IV.
        /// </summary>
        /// <seealso cref="decryptorKey"/>
        private byte[] decryptorIv;

        /// <summary>
        /// The encryption key that may carry state from a prior crypto operation.
        /// </summary>
        /// <seealso cref="encryptorIv"/>
        private SafeKeyHandle encryptorKey;

        /// <summary>
        /// The decryption key that may carry state from a prior crypto operation.
        /// </summary>
        /// <seealso cref="decryptorIv"/>
        private SafeKeyHandle decryptorKey;

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

        /// <summary>
        /// Gets the symmetric algorithm provider that created this key, if applicable.
        /// </summary>
        internal SymmetricKeyAlgorithmProvider SymmetricAlgorithmProvider => this.symmetricAlgorithmProvider;

        /// <inheritdoc />
        protected override SafeKeyHandle Key => this.GetInitializedKey(ref this.encryptorKey, null);

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                this.encryptorKey?.Dispose();
                this.decryptorKey?.Dispose();
            }

            base.Dispose(disposing);
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] plaintext, byte[] iv)
        {
            Verify.Operation(!this.Mode.IsAuthenticated(), "Cannot encrypt using this function when using an authenticated block chaining mode.");

            var key = this.GetInitializedKey(ref this.encryptorKey, iv);
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
            this.encryptorIv = CopyBufferOrNull(iv) ?? this.encryptorIv;

            byte[] cipherText = BCryptEncrypt(
                key,
                plaintext,
                IntPtr.Zero,
                this.encryptorIv,
                this.flags).ToArray();
            return cipherText;
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] ciphertext, byte[] iv)
        {
            Requires.NotNull(ciphertext, nameof(ciphertext));
            Requires.Argument(this.IsValidInputSize(ciphertext.Length), nameof(ciphertext), "Length is not a multiple of block size and no padding is selected.");
            Verify.Operation(!this.Mode.IsAuthenticated(), "Cannot encrypt using this function when using an authenticated block chaining mode.");

            var key = this.GetInitializedKey(ref this.decryptorKey, iv);
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
            this.decryptorIv = CopyBufferOrNull(iv) ?? this.decryptorIv;

            byte[] plainText = BCryptDecrypt(
                key,
                ciphertext,
                IntPtr.Zero,
                this.decryptorIv,
                this.flags).ToArray();
            return plainText;
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateEncryptor(byte[] iv)
        {
            return new BCryptEncryptTransform(this, iv);
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateDecryptor(byte[] iv)
        {
            return new BCryptDecryptTransform(this, iv);
        }

        protected override string GetBCryptBlobType(CryptographicPrivateKeyBlobType blobType)
        {
            throw new NotImplementedException();
        }

        protected override string GetBCryptBlobType(CryptographicPublicKeyBlobType blobType)
        {
            throw new NotImplementedException();
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

        /// <summary>
        /// Creates a zero IV buffer or a copy of the specified buffer.
        /// </summary>
        /// <param name="iv">The IV supplied by the caller.</param>
        /// <returns>A copy of <paramref name="iv"/> if not null; otherwise a zero-filled buffer.</returns>
        private byte[] CopyOrZeroIV(byte[] iv)
        {
            if (iv != null)
            {
                return iv.ToArray();
            }
            else if (!this.Mode.UsesIV())
            {
                // Don't create an IV when it doesn't apply.
                return null;
            }
            else
            {
                return new byte[this.symmetricAlgorithmProvider.BlockLength];
            }
        }

        private SafeKeyHandle GetInitializedKey(ref SafeKeyHandle key, byte[] iv)
        {
            if (key == null || key.IsClosed || !this.CanStreamAcrossTopLevelCipherOperations || iv != null)
            {
                key?.Dispose();
                try
                {
                    key = BCryptGenerateSymmetricKey(this.symmetricAlgorithmProvider.Algorithm, this.keyMaterial);
                }
                catch (Win32Exception ex)
                {
                    throw new ArgumentException(ex.Message, ex);
                }
            }

            return key;
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

        private abstract class BCryptCipherTransform : ICryptoTransform
        {
            /// <summary>
            /// An shareable, reusable empty byte array.
            /// </summary>
            protected static readonly byte[] EmptyBuffer = new byte[0];

            /// <summary>
            /// The cryptographic key that created this transform.
            /// </summary>
            protected readonly SymmetricCryptographicKey baseKey;

            /// <summary>
            /// The key that may carry state from a prior crypto operation.
            /// </summary>
            /// <seealso cref="iv"/>
            protected readonly SafeKeyHandle platformKey;

            /// <summary>
            /// The IV to use for the next transform operation.
            /// </summary>
            protected readonly byte[] iv;

            /// <summary>
            /// Initializes a new instance of the <see cref="BCryptCipherTransform"/> class.
            /// </summary>
            /// <param name="baseKey">The key that may carry state from a prior crypto operation.</param>
            /// <param name="platformKey">The stateful platform key.</param>
            /// <param name="iv">The IV to use for the next transform operation.</param>
            internal BCryptCipherTransform(SymmetricCryptographicKey baseKey, SafeKeyHandle platformKey, byte[] iv)
            {
                Requires.NotNull(baseKey, nameof(baseKey));
                Requires.NotNull(platformKey, nameof(platformKey));

                this.baseKey = baseKey;
                this.iv = baseKey.CopyOrZeroIV(iv);
                this.platformKey = platformKey;
            }

            /// <inheritdoc />
            public bool CanReuseTransform => false;

            /// <inheritdoc />
            public bool CanTransformMultipleBlocks => true;

            /// <inheritdoc />
            public int InputBlockSize => this.baseKey.SymmetricAlgorithmProvider.BlockLength;

            /// <inheritdoc />
            public int OutputBlockSize => this.baseKey.SymmetricAlgorithmProvider.BlockLength;

            /// <inheritdoc />
            public void Dispose()
            {
                this.platformKey.Dispose();
            }

            /// <inheritdoc />
            public abstract int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset);

            /// <inheritdoc />
            public abstract byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount);
        }

        private class BCryptEncryptTransform : BCryptCipherTransform
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="BCryptEncryptTransform"/> class.
            /// </summary>
            /// <param name="baseKey">The key that may carry state from a prior crypto operation.</param>
            /// <param name="iv">The IV to use for the next transform operation.</param>
            internal BCryptEncryptTransform(SymmetricCryptographicKey baseKey, byte[] iv)
                : base(baseKey, baseKey.GetInitializedKey(ref baseKey.encryptorKey, iv), iv)
            {
            }

            /// <inheritdoc />
            public override unsafe int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                int cbResult;
                BCryptEncrypt(
                    this.platformKey,
                    new ArraySegment<byte>(inputBuffer, inputOffset, inputCount),
                    null,
                    this.iv.AsArraySegment(),
                    new ArraySegment<byte>(outputBuffer, outputOffset, outputBuffer.Length - outputOffset),
                    out cbResult,
                    BCryptEncryptFlags.None).ThrowOnError();
                return cbResult;
            }

            /// <inheritdoc />
            public override unsafe byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                switch (this.baseKey.Padding)
                {
                    case SymmetricAlgorithmPadding.None:
                        Requires.Argument(this.baseKey.IsValidInputSize(inputCount), nameof(inputCount), "Length is not a non-zero multiple of block size and no padding is selected.");

                        if (inputCount == 0)
                        {
                            return EmptyBuffer;
                        }

                        break;
                    case SymmetricAlgorithmPadding.PKCS7:
                        break;
                    case SymmetricAlgorithmPadding.Zeros:
                        // We have to implement this padding ourselves.
                        if (inputCount == 0)
                        {
                            return EmptyBuffer;
                        }

                        CryptoUtilities.ApplyZeroPadding(
                            ref inputBuffer,
                            this.baseKey.symmetricAlgorithmProvider.BlockLength,
                            ref inputOffset,
                            ref inputCount);
                        break;
                    default:
                        throw new NotSupportedException();
                }

                int cbResult;
                BCryptEncrypt(
                    this.platformKey,
                    new ArraySegment<byte>(inputBuffer, inputOffset, inputCount),
                    null,
                    this.iv.AsArraySegment(),
                    default(ArraySegment<byte>),
                    out cbResult,
                    this.baseKey.flags).ThrowOnError();

                byte[] output = new byte[cbResult];
                BCryptEncrypt(
                    this.platformKey,
                    new ArraySegment<byte>(inputBuffer, inputOffset, inputCount),
                    null,
                    this.iv.AsArraySegment(),
                    new ArraySegment<byte>(output),
                    out cbResult,
                    this.baseKey.flags).ThrowOnError();

                Array.Resize(ref output, cbResult);
                return output;
            }
        }

        private class BCryptDecryptTransform : BCryptCipherTransform
        {
            /// <summary>
            /// The buffer with the last block's worth of ciphertext, which may
            /// be needed when depadding.
            /// </summary>
            private byte[] depadBuffer;

            /// <summary>
            /// Initializes a new instance of the <see cref="BCryptDecryptTransform"/> class.
            /// </summary>
            /// <param name="baseKey">The key that may carry state from a prior crypto operation.</param>
            /// <param name="iv">The IV to use for the next transform operation.</param>
            internal BCryptDecryptTransform(SymmetricCryptographicKey baseKey, byte[] iv)
                : base(baseKey, baseKey.GetInitializedKey(ref baseKey.decryptorKey, iv), iv)
            {
            }

            /// <inheritdoc />
            public override unsafe int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                Requires.NotNull(inputBuffer, nameof(inputBuffer));
                Requires.Range(inputCount > 0 && (inputCount % this.InputBlockSize) == 0, nameof(inputCount), "Positive integer multiple of input block size required.");

                int cbResult, bytesWritten = 0;
                if (this.baseKey.Padding != SymmetricAlgorithmPadding.None && this.baseKey.Padding != SymmetricAlgorithmPadding.Zeros)
                {
                    if (this.depadBuffer == null)
                    {
                        this.depadBuffer = new byte[this.InputBlockSize];
                    }
                    else
                    {
                        BCryptDecrypt(
                            this.platformKey,
                            new ArraySegment<byte>(this.depadBuffer, 0, this.depadBuffer.Length),
                            null,
                            this.iv.AsArraySegment(),
                            new ArraySegment<byte>(outputBuffer, outputOffset, outputBuffer.Length - outputOffset),
                            out cbResult,
                            BCryptEncryptFlags.None).ThrowOnError();
                        outputOffset += cbResult;
                        bytesWritten += cbResult;
                    }

                    // We need to capture the last block's worth of data from this input in case
                    // it turns out to be the very last block (which will need to be depadded).
                    Array.Copy(inputBuffer, inputOffset + inputCount - this.InputBlockSize, this.depadBuffer, 0, this.InputBlockSize);
                    inputCount -= this.InputBlockSize;
                }

                if (inputCount > 0)
                {
                    BCryptDecrypt(
                        this.platformKey,
                        new ArraySegment<byte>(inputBuffer, inputOffset, inputCount),
                        null,
                        this.iv.AsArraySegment(),
                        new ArraySegment<byte>(outputBuffer, outputOffset, outputBuffer.Length - outputOffset),
                        out cbResult,
                        BCryptEncryptFlags.None).ThrowOnError();
                    bytesWritten += cbResult;
                }

                return bytesWritten;
            }

            /// <inheritdoc />
            public override unsafe byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                int cbResult;
                byte[] output;
                int depadBufferPlaintextLength = 0;

                if (this.depadBuffer != null)
                {
                    // Decrypt the depad buffer in-place.
                    // If we have any input in this call at all, then *that* is what gets depadded.
                    var flags = inputCount > 0 ? BCryptEncryptFlags.None : this.baseKey.flags;
                    BCryptDecrypt(
                        this.platformKey,
                        new ArraySegment<byte>(this.depadBuffer),
                        null,
                        this.iv.AsArraySegment(),
                        new ArraySegment<byte>(this.depadBuffer),
                        out depadBufferPlaintextLength,
                        flags).ThrowOnError();
                }

                BCryptDecrypt(
                    this.platformKey,
                    new ArraySegment<byte>(inputBuffer, inputOffset, inputCount),
                    null,
                    this.iv.AsArraySegment(),
                    default(ArraySegment<byte>),
                    out cbResult,
                    this.baseKey.flags).ThrowOnError();

                output = new byte[depadBufferPlaintextLength + cbResult];
                if (this.depadBuffer != null)
                {
                    Array.Copy(this.depadBuffer, 0, output, 0, depadBufferPlaintextLength);
                    this.depadBuffer = null;
                }

                if (inputCount > 0)
                {
                    BCryptDecrypt(
                        this.platformKey,
                        new ArraySegment<byte>(inputBuffer, inputOffset, inputCount),
                        null,
                        this.iv.AsArraySegment(),
                        new ArraySegment<byte>(output, depadBufferPlaintextLength, output.Length - depadBufferPlaintextLength),
                        out cbResult,
                        this.baseKey.flags).ThrowOnError();
                }

                Array.Resize(ref output, depadBufferPlaintextLength + cbResult);
                return output;
            }
        }
    }
}
