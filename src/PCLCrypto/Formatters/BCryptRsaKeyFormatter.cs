// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#if !SILVERLIGHT

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Linq;
    using System.Numerics;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading.Tasks;
    using PCLCrypto.Formatters;
    using PInvoke;
    using Validation;
    using static PInvoke.BCrypt;

    /// <summary>
    /// Formats an RSA key as BCrypt.dll does.
    /// Known as an "RSA Public Key Blob", "RSA Private Key Blob", or "Full RSA Private Key Blob".
    /// </summary>
    /// <remarks>
    /// The key format is documented here: https://msdn.microsoft.com/en-us/library/windows/desktop/aa375531(v=vs.85).aspx
    /// </remarks>
    internal class BCryptRsaKeyFormatter : KeyFormatter
    {
        /// <summary>
        /// The magic number to use in the header, based on the desired private key type
        /// selected in the constructor.
        /// </summary>
        private readonly BCRYPT_RSAKEY_BLOB.MagicNumber keyType;

        /// <summary>
        /// Initializes a new instance of the <see cref="BCryptRsaKeyFormatter"/> class.
        /// </summary>
        /// <param name="privateKeyType">
        /// Either <see cref="CryptographicPrivateKeyBlobType.BCryptFullPrivateKey"/> or <see cref="CryptographicPrivateKeyBlobType.BCryptPrivateKey"/>
        /// </param>
        public BCryptRsaKeyFormatter(CryptographicPrivateKeyBlobType privateKeyType)
        {
            Requires.Argument(privateKeyType == CryptographicPrivateKeyBlobType.BCryptFullPrivateKey || privateKeyType == CryptographicPrivateKeyBlobType.BCryptPrivateKey, nameof(privateKeyType), "Not a BCrypt key blob format.");
            this.keyType = privateKeyType == CryptographicPrivateKeyBlobType.BCryptFullPrivateKey
                ? BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAFULLPRIVATE_MAGIC
                : BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAPRIVATE_MAGIC;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BCryptRsaKeyFormatter"/> class.
        /// </summary>
        /// <param name="publicKeyType">Must always be <see cref="CryptographicPublicKeyBlobType.BCryptPublicKey"/></param>
        public BCryptRsaKeyFormatter(CryptographicPublicKeyBlobType publicKeyType)
        {
            Requires.Argument(publicKeyType == CryptographicPublicKeyBlobType.BCryptPublicKey, nameof(publicKeyType), "Not a BCrypt key blob format.");
            this.keyType = BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAPUBLIC_MAGIC;
        }

        /// <summary>
        /// Gets a value indicating whether to include the private key when serializing.
        /// </summary>
        protected bool IncludePrivateKey => this.keyType != BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAPUBLIC_MAGIC;

        /// <summary>
        /// Gets a value indicating whether to include the optional parameters of the private key when serializing the private key.
        /// </summary>
        protected bool IncludeFullPrivateKey => this.keyType == BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAFULLPRIVATE_MAGIC;

        /// <inheritdoc />
        protected override unsafe RSAParameters ReadCore(Stream stream)
        {
            var parameters = default(RSAParameters);
            var reader = new BinaryReader(stream);

#if DESKTOP
            int headerSize = Marshal.SizeOf(typeof(BCRYPT_RSAKEY_BLOB));
#else
            int headerSize = Marshal.SizeOf<BCRYPT_RSAKEY_BLOB>();
#endif
            byte[] headerBytes = reader.ReadBytes(headerSize);
            BCRYPT_RSAKEY_BLOB header;
            fixed (byte* pHeaderBytes = headerBytes)
            {
#if DESKTOP
                header = (BCRYPT_RSAKEY_BLOB)Marshal.PtrToStructure(new IntPtr(pHeaderBytes), typeof(BCRYPT_RSAKEY_BLOB));
#else
                header = Marshal.PtrToStructure<BCRYPT_RSAKEY_BLOB>(new IntPtr(pHeaderBytes));
#endif
            }

            VerifyFormat(this.keyType == header.Magic, "Unexpected key blob type.");
            parameters.Exponent = reader.ReadBytes(header.cbPublicExp);
            parameters.Modulus = reader.ReadBytes(header.cbModulus);

            if (header.Magic != BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAPUBLIC_MAGIC)
            {
                parameters.P = reader.ReadBytes(header.cbPrime1);
                parameters.Q = reader.ReadBytes(header.cbPrime2);

                if (header.Magic != BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAPRIVATE_MAGIC)
                {
                    VerifyFormat(header.Magic == BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAFULLPRIVATE_MAGIC);
                    parameters.DP = reader.ReadBytes(header.cbPrime1);
                    parameters.DQ = reader.ReadBytes(header.cbPrime2);
                    parameters.InverseQ = reader.ReadBytes(header.cbPrime1);
                    parameters.D = reader.ReadBytes(header.cbModulus);
                }
            }

            return parameters;
        }

        /// <inheritdoc />
        protected override unsafe void WriteCore(Stream stream, RSAParameters parameters)
        {
            var writer = new BinaryWriter(stream);
            var header = default(BCRYPT_RSAKEY_BLOB);

            header.Magic = this.keyType;

            Verify.Operation(parameters.D != null || !this.IncludeFullPrivateKey, "Cannot serialize missing full private key data.");
            Verify.Operation(parameters.P != null || !this.IncludePrivateKey, "Cannot serialize missing private key.");

            var modulus = TrimLeadingZero(parameters.Modulus);
            var p = TrimLeadingZero(parameters.P);
            var q = TrimLeadingZero(parameters.Q);

            header.cbPublicExp = parameters.Exponent.Length;
            header.cbModulus = modulus.Length;
            header.cbPrime1 = p?.Length ?? 0;
            header.cbPrime2 = q?.Length ?? 0;
            header.BitLength = modulus.Length * 8;

#if DESKTOP
            int headerSize = Marshal.SizeOf(typeof(BCRYPT_RSAKEY_BLOB));
#else
            int headerSize = Marshal.SizeOf<BCRYPT_RSAKEY_BLOB>();
#endif
            byte[] headerBytes = new byte[headerSize];
            fixed (byte* pHeaderBytes = headerBytes)
            {
#if DESKTOP
                Marshal.StructureToPtr(header, new IntPtr(pHeaderBytes), false);
#else
                Marshal.StructureToPtr(header, new IntPtr(pHeaderBytes), false);
#endif
            }

            writer.Write(headerBytes);
            writer.Write(parameters.Exponent);
            writer.Write(modulus);

            if (this.IncludePrivateKey)
            {
                writer.Write(p);
                writer.Write(q);

                if (this.IncludeFullPrivateKey)
                {
                    writer.Write(TrimOrPadZeroToLength(parameters.DP, header.cbPrime1));
                    writer.Write(TrimOrPadZeroToLength(parameters.DQ, header.cbPrime2));
                    writer.Write(TrimOrPadZeroToLength(parameters.InverseQ, header.cbPrime1));
                    writer.Write(TrimOrPadZeroToLength(parameters.D, header.cbModulus));
                }
            }
        }
    }
}
#endif
