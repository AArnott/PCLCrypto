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
                else
                {
                    // We have to calculate the missing values.
                    parameters = FillInFullPrivateKey(parameters);
                }
            }

            return parameters;
        }

        /// <inheritdoc />
        protected override unsafe void WriteCore(Stream stream, RSAParameters parameters)
        {
            var writer = new BinaryWriter(stream);
            var header = default(BCRYPT_RSAKEY_BLOB);

            header.Magic = parameters.D != null ? BCRYPT_RSAKEY_BLOB.MagicNumber.BCRYPT_RSAFULLPRIVATE_MAGIC
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

        private static RSAParameters FillInFullPrivateKey(RSAParameters rsa)
        {
            return Create(rsa.P, rsa.Q, rsa.Exponent, rsa.Modulus);
        }

        /// <summary>
        /// Fills out the rest of an <see cref="RSAParameters"/> structure
        /// given the public key data and the secrets P and Q.
        /// </summary>
        /// <param name="p">The P parameter (Big endian)</param>
        /// <param name="q">The Q parameter (Big endian)</param>
        /// <param name="exponent">The e (public exponent) (big endian)</param>
        /// <param name="modulus">The modulus (big endian)</param>
        /// <returns>The fully calculated <see cref="RSAParameters"/></returns>
        private static RSAParameters Create(byte[] p, byte[] q, byte[] exponent, byte[] modulus)
        {
            var addlParameters = GetFullPrivateParameters(
                p: new BigInteger(CopyAndReverse(p)),
                q: new BigInteger(CopyAndReverse(q)),
                e: new BigInteger(CopyAndReverse(exponent)));

            return new RSAParameters
            {
                P = p,
                Q = q,
                Exponent = exponent,
                Modulus = modulus,
                D = addlParameters.D,
                DP = addlParameters.DP,
                DQ = addlParameters.DQ,
                InverseQ = addlParameters.InverseQ,
            };
        }

        /// <summary>
        /// Creates an <see cref="RSAParameters"/> structure initialized with
        /// the values for D, DP, DQ, InverseQ.
        /// </summary>
        /// <param name="p">The P parameter.</param>
        /// <param name="q">The Q parameter.</param>
        /// <param name="e">The e parameter.</param>
        /// <returns>An <see cref="RSAParameters"/> structure initialized with
        /// the values for D, DP, DQ, InverseQ.</returns>
        private static RSAParameters GetFullPrivateParameters(BigInteger p, BigInteger q, BigInteger e)
        {
            var n = p * q;
            var phiOfN = n - p - q + 1; // OR: (p - 1) * (q - 1);

            var d = ModInverse(e, phiOfN);
            Debug.Assert((d * e) % phiOfN == 1, "mod inverse didn't meet goal.");

            var dp = d % (p - 1);
            var dq = d % (q - 1);

            var qInv = ModInverse(q, p);
            ////Debug.Assert(1 == (qInv * q) % p); // this tends to fail. :(

            return new RSAParameters
            {
                D = CopyAndReverse(d.ToByteArray()),
                DP = CopyAndReverse(dp.ToByteArray()),
                DQ = CopyAndReverse(dq.ToByteArray()),
                InverseQ = CopyAndReverse(qInv.ToByteArray()),
            };
        }

        /// <summary>
        /// Calculates the modular multiplicative inverse of <paramref name="a"/> modulo <paramref name="n"/>
        /// using the extended Euclidean algorithm.
        /// </summary>
        /// <param name="a">The 'a' factor (where <paramref name="a" /> * t=1 (mod <paramref name="n"/>) where t is the result.</param>
        /// <param name="n">The 'n' factor (the modulo value).</param>
        /// <returns>Result of modular multiplicative inverse.</returns>
        /// <remarks>
        /// This implementation comes from the pseudocode defining the inverse(a, n) function at
        /// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
        /// and the javascript sample provided at:
        /// https://github.com/bobvanluijt/Bitcoin-explained/blob/master/RSA.js
        /// </remarks>
        private static BigInteger ModInverse(BigInteger a, BigInteger n)
        {
            BigInteger t = 0, nt = 1, r = n, nr = a;

            if (n < 0)
            {
                n = -n;
            }

            if (a < 0)
            {
                a = n - (-a % n);
            }

            while (nr != 0)
            {
                var quot = r / nr;

                var tmp = nt;
                nt = t - (quot * nt);
                t = tmp;

                tmp = nr;
                nr = r - (quot * nr);
                r = tmp;
            }

            if (r > 1)
            {
                throw new ArgumentException(nameof(a) + " is not convertible.");
            }

            if (t < 0)
            {
                t += n;
            }

            return t;
        }
    }
}
#endif
