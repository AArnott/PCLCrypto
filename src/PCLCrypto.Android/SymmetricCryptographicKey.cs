//-----------------------------------------------------------------------
// <copyright file="SymmetricCryptographicKey.cs" company="Andrew Arnott">
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
    using Java.Security;
    using Javax.Crypto;
    using Javax.Crypto.Spec;
    using Validation;

    /// <summary>
    /// A .NET Framework implementation of <see cref="ICryptographicKey"/> for use with symmetric algorithms.
    /// </summary>
    internal class SymmetricCryptographicKey : CryptographicKey, ICryptographicKey, IDisposable
    {
        /// <summary>
        /// The symmetric algorithm.
        /// </summary>
        private readonly SymmetricAlgorithm algorithm;

        /// <summary>
        /// The cipher.
        /// </summary>
        private readonly Cipher cipher;

        /// <summary>
        /// The symmetric key.
        /// </summary>
        private readonly IKey key;

        /// <summary>
        /// A value indicating whether <see cref="cipher"/> has already been initialized.
        /// </summary>
        private bool cipherInitialized;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricCryptographicKey" /> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="keyMaterial">The key.</param>
        internal SymmetricCryptographicKey(SymmetricAlgorithm algorithm, byte[] keyMaterial)
        {
            Requires.NotNull(keyMaterial, "keyMaterial");

            try
            {
                this.algorithm = algorithm;
                this.key = new SecretKeySpec(keyMaterial, this.algorithm.GetName().GetString());

                try
                {
                    var cipherName = this.GetCipherAcquisitionName();
                    this.cipher = Cipher.GetInstance(cipherName.ToString());
                }
                catch (NoSuchAlgorithmException ex)
                {
                    throw new NotSupportedException("Algorithm not supported.", ex);
                }
            }
            catch
            {
                this.key.DisposeIfNotNull();
                this.cipher.DisposeIfNotNull();
                throw;
            }
        }

        /// <inheritdoc />
        public int KeySize
        {
            get { throw new NotImplementedException(); }
        }

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
            this.cipher.Dispose();
        }

        /// <inheritdoc />
        protected internal override byte[] Encrypt(byte[] data, byte[] iv)
        {
            Requires.Argument(iv == null || this.algorithm.UsesIV(), "iv", "IV supplied but does not apply to this cipher.");
            this.InitializeCipher(CipherMode.EncryptMode, iv);
            return this.algorithm.IsBlockCipher()
                ? this.cipher.DoFinal(data)
                : this.cipher.Update(data);
        }

        /// <inheritdoc />
        protected internal override byte[] Decrypt(byte[] data, byte[] iv)
        {
            Requires.Argument(iv == null || this.algorithm.UsesIV(), "iv", "IV supplied but does not apply to this cipher.");
            this.InitializeCipher(CipherMode.DecryptMode, iv);
            try
            {
                return this.algorithm.IsBlockCipher()
                    ? this.cipher.DoFinal(data)
                    : this.cipher.Update(data);
            }
            catch (IllegalBlockSizeException ex)
            {
                throw new ArgumentException("Illegal block size.", ex);
            }
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateEncryptor(byte[] iv)
        {
            this.InitializeCipher(CipherMode.EncryptMode, iv);
            return new CryptoTransformAdaptor(this.cipher);
        }

        /// <inheritdoc />
        protected internal override ICryptoTransform CreateDecryptor(byte[] iv)
        {
            this.InitializeCipher(CipherMode.DecryptMode, iv);
            return new CryptoTransformAdaptor(this.cipher);
        }

        /// <summary>
        /// Gets the padding substring to include in the string
        /// passed to <see cref="Cipher.GetInstance(string)"/>
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A value such as "PKCS7Padding", or <c>null</c> if no padding.</returns>
        private static string GetPadding(SymmetricAlgorithm algorithm)
        {
            switch (algorithm.GetPadding())
            {
                case SymmetricAlgorithmPadding.None:
                    return null;
                case SymmetricAlgorithmPadding.PKCS7:
                    return "PKCS7Padding";
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
            else if (!this.algorithm.UsesIV())
            {
                // Don't create an IV when it doesn't apply.
                return null;
            }
            else
            {
                return new byte[this.cipher.BlockSize];
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
        private void InitializeCipher(CipherMode mode, byte[] iv)
        {
            if (this.cipherInitialized && !this.algorithm.IsBlockCipher())
            {
                // Avoid reseting the state of a streaming cipher.
                return;
            }

            try
            {
                iv = this.ThisOrDefaultIV(iv);
                using (var ivspec = iv != null ? new IvParameterSpec(iv) : null)
                {
                    try
                    {
                        cipher.Init(mode, this.key, ivspec);
                        this.cipherInitialized = true;
                    }
                    catch (Java.Security.InvalidKeyException ex)
                    {
                        throw new ArgumentException(ex.Message, ex);
                    }
                }
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
            var cipherName = new StringBuilder(this.algorithm.GetName().GetString());
            if (this.algorithm.IsBlockCipher())
            {
                cipherName.Append("/");
                cipherName.Append(this.algorithm.GetMode());
                string paddingString = GetPadding(this.algorithm);
                if (paddingString != null)
                {
                    cipherName.Append("/");
                    cipherName.Append(paddingString);
                }
            }

            return cipherName;
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
            /// Initializes a new instance of the <see cref="CryptoTransformAdaptor"/> class.
            /// </summary>
            /// <param name="transform">The transform.</param>
            internal CryptoTransformAdaptor(Cipher transform)
            {
                Requires.NotNull(transform, "transform");
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
                get { return this.transform.BlockSize; }
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
                return this.transform.DoFinal(inputBuffer, inputOffset, inputCount);
            }

            /// <inheritdoc />
            public void Dispose()
            {
                this.transform.Dispose();
            }
        }
    }
}
