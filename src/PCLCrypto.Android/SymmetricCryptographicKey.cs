// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Java.Security;
    using Javax.Crypto;
    using Javax.Crypto.Spec;
    using Validation;

    /// <summary>
    /// A .NET Framework implementation of <see cref="ICryptographicKey"/> for use with symmetric algorithms.
    /// </summary>
    internal partial class SymmetricCryptographicKey : CryptographicKey, ICryptographicKey, IDisposable
    {
        /// <summary>
        /// The symmetric key.
        /// </summary>
        private readonly IKey key;

        /// <summary>
        /// The cipher to use for encryption.
        /// </summary>
        private Cipher encryptingCipher;

        /// <summary>
        /// The cipher to use for decryption.
        /// </summary>
        private Cipher decryptingCipher;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricCryptographicKey" /> class.
        /// </summary>
        /// <param name="name">The name of the base algorithm to use.</param>
        /// <param name="mode">The algorithm's mode (i.e. streaming or some block mode).</param>
        /// <param name="padding">The padding to use.</param>
        /// <param name="keyMaterial">The key.</param>
        internal SymmetricCryptographicKey(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding, byte[] keyMaterial)
        {
            Requires.NotNull(keyMaterial, "keyMaterial");

            if (name == SymmetricAlgorithmName.Aes && mode == SymmetricAlgorithmMode.Ccm && padding == SymmetricAlgorithmPadding.None)
            {
                // On Android encryption misbehaves causing our unit tests to fail.
                throw new NotSupportedException();
            }

            this.Name = name;
            this.Mode = mode;
            this.Padding = padding;
            this.key = new SecretKeySpec(keyMaterial, this.Name.GetString());
            this.KeySize = keyMaterial.Length * 8;
        }

        /// <inheritdoc />
        public int KeySize { get; private set; }

        /// <inheritdoc />
        public byte[] Export(CryptographicPrivateKeyBlobType blobType = CryptographicPrivateKeyBlobType.Pkcs8RawPrivateKeyInfo)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public byte[] ExportPublicKey(CryptographicPublicKeyBlobType blobType = CryptographicPublicKeyBlobType.X509SubjectPublicKeyInfo)
        {
            throw new NotSupportedException();
        }

        /// <inheritdoc />
        public void Dispose()
        {
            this.key.Dispose();
            this.encryptingCipher.DisposeIfNotNull();
            this.decryptingCipher.DisposeIfNotNull();
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[] iv)
        {
            bool paddingInUse = this.Padding != SymmetricAlgorithmPadding.None;
            Requires.Argument(iv == null || this.Mode.UsesIV(), "iv", "IV supplied but does not apply to this cipher.");

            this.InitializeCipher(CipherMode.EncryptMode, iv, ref this.encryptingCipher);
            Requires.Argument(paddingInUse || this.IsValidInputSize(data.Length), "data", "Length does not a multiple of block size and no padding is selected.");

            return this.Mode.IsBlockCipher()
                ? this.encryptingCipher.DoFinal(data)
                : this.encryptingCipher.Update(data);
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            Requires.Argument(iv == null || this.Mode.UsesIV(), "iv", "IV supplied but does not apply to this cipher.");

            this.InitializeCipher(CipherMode.DecryptMode, iv, ref this.decryptingCipher);
            Requires.Argument(this.IsValidInputSize(data.Length), "data", "Length does not a multiple of block size and no padding is selected.");

            try
            {
                return this.Mode.IsBlockCipher()
                    ? this.decryptingCipher.DoFinal(data)
                    : this.decryptingCipher.Update(data);
            }
            catch (IllegalBlockSizeException ex)
            {
                throw new ArgumentException("Illegal block size.", ex);
            }
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateEncryptor(byte[] iv)
        {
            this.InitializeCipher(CipherMode.EncryptMode, iv, ref this.encryptingCipher);
            return new CryptoTransformAdaptor(this.Name, this.Mode, this.Padding, this.encryptingCipher);
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateDecryptor(byte[] iv)
        {
            this.InitializeCipher(CipherMode.DecryptMode, iv, ref this.decryptingCipher);
            return new CryptoTransformAdaptor(this.Name, this.Mode, this.Padding, this.decryptingCipher);
        }

        /// <summary>
        /// Gets the padding substring to include in the string
        /// passed to <see cref="Cipher.GetInstance(string)"/>
        /// </summary>
        /// <param name="padding">The padding.</param>
        /// <returns>A value such as "PKCS7Padding", or "NoPadding" if no padding.</returns>
        private static string GetPaddingName(SymmetricAlgorithmPadding padding)
        {
            switch (padding)
            {
                case SymmetricAlgorithmPadding.None:
                    return "NoPadding";
                case SymmetricAlgorithmPadding.PKCS7:
                    return "PKCS7Padding";
                case SymmetricAlgorithmPadding.Zeros:
                    throw new NotImplementedException(); // TODO
                default:
                    throw new NotSupportedException();
            }
        }

        /// <summary>
        /// Creates a zero IV buffer.
        /// </summary>
        /// <param name="iv">The IV supplied by the caller.</param>
        /// <returns>
        ///   <paramref name="iv" /> if not null; otherwise a zero-filled buffer.
        /// </returns>
        private byte[] ThisOrDefaultIV(byte[] iv)
        {
            if (iv != null)
            {
                return iv;
            }
            else if (!this.Mode.UsesIV())
            {
                // Don't create an IV when it doesn't apply.
                return null;
            }
            else
            {
                var cipher = this.encryptingCipher ?? this.decryptingCipher;
                return new byte[cipher.BlockSize];
            }
        }

        /// <summary>
        /// Initializes a new cipher.
        /// </summary>
        /// <param name="mode">The mode.</param>
        /// <param name="iv">The initialization vector to use.</param>
        /// <returns>
        /// The initialized cipher.
        /// </returns>
        private Cipher GetInitializedCipher(CipherMode mode, byte[] iv)
        {
            switch (mode)
            {
                case CipherMode.DecryptMode:
                    this.InitializeCipher(mode, iv, ref this.decryptingCipher);
                    return this.decryptingCipher;
                case CipherMode.EncryptMode:
                    this.InitializeCipher(mode, iv, ref this.encryptingCipher);
                    return this.encryptingCipher;
                default:
                    throw new ArgumentException();
            }
        }

        /// <summary>
        /// Initializes the cipher if it has not yet been initialized.
        /// </summary>
        /// <param name="mode">The mode.</param>
        /// <param name="iv">The iv.</param>
        /// <param name="cipher">The cipher.</param>
        /// <exception cref="System.ArgumentException">
        /// Invalid algorithm parameter.
        /// </exception>
        /// <exception cref="System.NotSupportedException">Algorithm not supported.</exception>
        private void InitializeCipher(CipherMode mode, byte[] iv, ref Cipher cipher)
        {
            try
            {
                bool newCipher = false;
                if (cipher == null)
                {
                    cipher = Cipher.GetInstance(this.GetCipherAcquisitionName().ToString());
                    newCipher = true;
                }

                if (this.Mode.IsBlockCipher() || newCipher)
                {
                    iv = this.ThisOrDefaultIV(iv);
                    using (var ivspec = iv != null ? new IvParameterSpec(iv) : null)
                    {
                        cipher.Init(mode, this.key, ivspec);
                    }
                }
            }
            catch (InvalidKeyException ex)
            {
                throw new ArgumentException(ex.Message, ex);
            }
            catch (NoSuchAlgorithmException ex)
            {
                throw new NotSupportedException("Algorithm not supported.", ex);
            }
            catch (InvalidAlgorithmParameterException ex)
            {
                throw new ArgumentException("Invalid algorithm parameter.", ex);
            }
        }

        /// <summary>
        /// Assembles a string to pass to <see cref="Cipher.GetInstance(string)"/>
        /// that identifies the algorithm, block mode and padding.
        /// </summary>
        /// <returns>A string such as "AES/CBC/PKCS7Padding</returns>
        private StringBuilder GetCipherAcquisitionName()
        {
            var cipherName = new StringBuilder(this.Name.GetString());
            if (this.Mode.IsBlockCipher())
            {
                cipherName.Append("/");
                cipherName.Append(this.Mode);
                cipherName.Append("/");
                cipherName.Append(GetPaddingName(this.Padding));
            }

            return cipherName;
        }

        /// <summary>
        /// Checks whether the given length is a valid one for an input buffer to the symmetric algorithm.
        /// </summary>
        /// <param name="lengthInBytes">The length of the input buffer in bytes.</param>
        /// <returns><c>true</c> if the size is allowed; <c>false</c> otherwise.</returns>
        private bool IsValidInputSize(int lengthInBytes)
        {
            var cipher = this.encryptingCipher ?? this.decryptingCipher;
            int blockSizeInBytes = SymmetricKeyAlgorithmProvider.GetBlockSize(this.Mode, cipher);
            return lengthInBytes > 0 && lengthInBytes % blockSizeInBytes == 0;
        }

        /// <summary>
        /// Adapts a platform Cipher to the PCL interface.
        /// </summary>
        private class CryptoTransformAdaptor : ICryptoTransform
        {
            /// <summary>
            /// The platform transform.
            /// </summary>
            private readonly Cipher transform;

            /// <summary>
            /// The algorithm.
            /// </summary>
            private readonly SymmetricAlgorithmName name;

            /// <summary>
            /// The mode.
            /// </summary>
            private readonly SymmetricAlgorithmMode mode;

            /// <summary>
            /// The padding.
            /// </summary>
            private readonly SymmetricAlgorithmPadding padding;

            /// <summary>
            /// Initializes a new instance of the <see cref="CryptoTransformAdaptor"/> class.
            /// </summary>
            /// <param name="name">The name of the base algorithm to use.</param>
            /// <param name="mode">The algorithm's mode (i.e. streaming or some block mode).</param>
            /// <param name="padding">The padding to use.</param>
            /// <param name="transform">The transform.</param>
            internal CryptoTransformAdaptor(SymmetricAlgorithmName name, SymmetricAlgorithmMode mode, SymmetricAlgorithmPadding padding, Cipher transform)
            {
                Requires.NotNull(transform, "transform");
                this.name = name;
                this.mode = mode;
                this.padding = padding;
                this.transform = transform;
            }

            /// <inheritdoc />
            public bool CanReuseTransform
            {
                get { return false; }
            }

            /// <inheritdoc />
            public bool CanTransformMultipleBlocks
            {
                get { return true; }
            }

            /// <inheritdoc />
            public int InputBlockSize
            {
                get { return SymmetricKeyAlgorithmProvider.GetBlockSize(this.mode, this.transform); }
            }

            /// <inheritdoc />
            public int OutputBlockSize
            {
                get { return this.transform.GetOutputSize(this.InputBlockSize); }
            }

            /// <inheritdoc />
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                return this.transform.Update(inputBuffer, inputOffset, inputCount, outputBuffer, outputOffset);
            }

            /// <inheritdoc />
            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                return this.mode.IsBlockCipher()
                    ? this.transform.DoFinal(inputBuffer, inputOffset, inputCount)
                    : this.transform.Update(inputBuffer, inputOffset, inputCount);
            }

            /// <inheritdoc />
            public void Dispose()
            {
                // Don't dispose of the transform because we share it with the instance of our parent class.
            }
        }
    }
}
