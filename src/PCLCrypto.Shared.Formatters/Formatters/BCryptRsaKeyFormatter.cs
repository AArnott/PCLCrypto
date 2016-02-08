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

            header.Magic =
                parameters.D != null ? BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAFULLPRIVATE_MAGIC
                : parameters.P != null ? BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAPRIVATE_MAGIC
                : BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAPUBLIC_MAGIC;

            var modulus = TrimLeadingZero(parameters.Modulus);

            header.cbPublicExp = parameters.Exponent.Length;
            header.cbModulus = modulus.Length;
            header.cbPrime1 = parameters.P?.Length ?? 0;
            header.cbPrime2 = parameters.Q?.Length ?? 0;
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

            if (parameters.P != null)
            {
                writer.Write(parameters.P);
                writer.Write(parameters.Q);

                if (parameters.D != null)
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
