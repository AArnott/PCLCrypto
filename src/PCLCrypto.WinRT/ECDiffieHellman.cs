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
    /// The WinRT implementation of the <see cref="IECDiffieHellman"/>.
    /// </summary>
    internal class ECDiffieHellman : IECDiffieHellman, IDisposableObservable
    {
        private SafeAlgorithmHandle platformAlgorithm;
        private SafeKeyHandle platformKey;

        private int keySize = 521;

        /// <summary>
        /// Initializes a new instance of the <see cref="ECDiffieHellman"/> class.
        /// </summary>
        internal ECDiffieHellman()
        {
            var foo = this.PlatformAlgorithm;
        }

        /// <inheritdoc />
        public int KeySize
        {
            get
            {
                return this.keySize;
            }

            set
            {
                if (this.keySize != value)
                {
                    Requires.Range(ECDiffieHellmanFactory.EcdhKeySizesAndAlgorithmNames.ContainsKey(value), nameof(value));
                    this.keySize = value;
                    this.Reset();
                }
            }
        }

        /// <inheritdoc />
        public IECDiffieHellmanPublicKey PublicKey
        {
            get
            {
                return new ECDiffieHellmanPublicKey(this.PlatformKey);
            }
        }

        /// <summary>
        /// Gets or sets the hash algorithm to use in the key derivation function.
        /// </summary>
        public HashAlgorithm HashAlgorithm { get; set; } = HashAlgorithm.Sha256;

        /// <inheritdoc />
        public bool IsDisposed { get; private set; }

        /// <summary>
        /// Gets the handle for the platform's algorithm, opening it if necessary.
        /// </summary>
        private SafeAlgorithmHandle PlatformAlgorithm
        {
            get
            {
                Verify.NotDisposed(this);
                if (this.platformAlgorithm == null)
                {
                    this.platformAlgorithm = ECDiffieHellmanFactory.BCryptOpenAlgorithmProvider(this.KeySize);
                }

                return this.platformAlgorithm;
            }
        }

        private SafeKeyHandle PlatformKey
        {
            get
            {
                if (this.platformKey == null)
                {
                    this.platformKey = BCryptGenerateKeyPair(
                        this.PlatformAlgorithm,
                        this.KeySize);
                    BCryptFinalizeKeyPair(this.platformKey);
                }

                return this.platformKey;
            }
        }

        /// <inheritdoc />
        public byte[] DeriveKeyMaterial(IECDiffieHellmanPublicKey otherParty)
        {
            Requires.NotNull(otherParty, nameof(otherParty));

            var publicKey = (ECDiffieHellmanPublicKey)otherParty;
            using (var secret = BCryptSecretAgreement(this.PlatformKey, publicKey.Key))
            {
                IntPtr hashAlgorithmPtr = IntPtr.Zero;
                try
                {
                    string hashAlgorithmString = HashAlgorithmProviderFactory.GetHashAlgorithmName(this.HashAlgorithm);
                    try
                    {
                    }
                    finally
                    {
                        // Do this in a finally so that ThreadAbortException doesn't interrupt the
                        // assignment of a successfully allocated pointer.
                        hashAlgorithmPtr = Marshal.StringToCoTaskMemUni(hashAlgorithmString);
                    }

                    var parameters = new List<BCryptBuffer>();
                    parameters.Add(new BCryptBuffer
                    {
                        cbBuffer = (hashAlgorithmString.Length + 1) * sizeof(char),
                        BufferType = BufferType.KDF_HASH_ALGORITHM,
                        pvBuffer = hashAlgorithmPtr,
                    });

                    const string kdf = KeyDerivationFunctions.HASH;
                    unsafe
                    {
                        fixed (BCryptBuffer* pParameters = parameters.ToArray())
                        {
                            var parameterDesc = new BCryptBufferDesc
                            {
                                ulVersion = 0,
                                cBuffers = parameters.Count,
                                pBuffers = new IntPtr(pParameters),
                            };

                            int secretLength;
                            BCryptDeriveKey(
                                secret,
                                kdf,
                                ref parameterDesc,
                                null,
                                0,
                                out secretLength,
                                BCryptDeriveKeyFlags.KDF_USE_SECRET_AS_HMAC_KEY_FLAG).ThrowOnError();

                            byte[] derivedKey = new byte[secretLength];
                            BCryptDeriveKey(
                                secret,
                                kdf,
                                ref parameterDesc,
                                derivedKey,
                                derivedKey.Length,
                                out secretLength,
                                0).ThrowOnError();
                            Assumes.True(secretLength == derivedKey.Length);
                            return derivedKey;
                        }
                    }
                }
                finally
                {
                    if (hashAlgorithmPtr != IntPtr.Zero)
                    {
                        Marshal.FreeCoTaskMem(hashAlgorithmPtr);
                    }
                }
            }
        }

        /// <summary>
        /// Disposes of managed resources associated with this instance.
        /// </summary>
        public void Dispose()
        {
            this.Reset();
            this.IsDisposed = true;
        }

        private void Reset()
        {
            this.platformKey?.Dispose();
            this.platformKey = null;
            this.platformAlgorithm?.Dispose();
            this.platformAlgorithm = null;
        }
    }
}
