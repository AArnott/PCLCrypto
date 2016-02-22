// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Diagnostics;
#if !SILVERLIGHT
    using System.Numerics;
    using Validation;
#endif

    /// <summary>
    /// Extension methods for the <see cref="RSAParameters"/> struct.
    /// </summary>
    internal static class RSAParametersExtensions
    {
        /// <summary>
        /// Gets a value indicating whether the specified <see cref="RSAParameters"/> carries private key data.
        /// </summary>
        /// <param name="rsa">The <see cref="RSAParameters"/> to check for private key data.</param>
        /// <returns><c>true</c> if private key data is included; <c>false</c> otherwise.</returns>
        internal static bool HasPrivateKey(this RSAParameters rsa) => rsa.P != null;

        /// <summary>
        /// Gets a value indicating whether the specified <see cref="RSAParameters"/> carries
        /// private key data including optional parametres.
        /// </summary>
        /// <param name="rsa">The <see cref="RSAParameters"/> to check for private key data.</param>
        /// <returns><c>true</c> if full private key data is included; <c>false</c> otherwise.</returns>
        internal static bool HasFullPrivateKeyData(this RSAParameters rsa) => rsa.InverseQ != null;

        /// <summary>
        /// Fills in missing optional private key data.
        /// </summary>
        /// <param name="rsa">The <see cref="RSAParameters"/> that contain a private key but not the optional parameters.</param>
        /// <returns>The fully populated private key data.</returns>
        internal static RSAParameters ComputeFullPrivateKeyData(this RSAParameters rsa)
        {
            if (rsa.HasFullPrivateKeyData())
            {
                return rsa;
            }

#if SILVERLIGHT
            throw new NotSupportedException("Silverlight does not allow calculating missing RSA private key data.");
#else
            return Create(rsa.P, rsa.Q, rsa.Exponent, rsa.Modulus);
#endif
        }

        /// <summary>
        /// Removes the private key data that can be recomputed given P and Q (private data).
        /// </summary>
        /// <param name="rsa">The <see cref="RSAParameters"/> that may contain optional private key data.</param>
        /// <returns>The <see cref="RSAParameters"/> that do not contain optional private key data, but may still contain (the minimum required) private key data.</returns>
        internal static RSAParameters StripOptionalPrivateKeyData(this RSAParameters rsa)
        {
            rsa.DP = null;
            rsa.DQ = null;
            rsa.InverseQ = null;
            rsa.D = null;
            return rsa;
        }

#if !SILVERLIGHT
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
                p: CryptoUtilities.FromPositiveBigEndian(p),
                q: CryptoUtilities.FromPositiveBigEndian(q),
                e: CryptoUtilities.FromPositiveBigEndian(exponent),
                n: CryptoUtilities.FromPositiveBigEndian(modulus));

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
        /// <param name="n">The modulus (<paramref name="p"/> * <paramref name="q"/>)</param>
        /// <returns>An <see cref="RSAParameters"/> structure initialized with
        /// the values for D, DP, DQ, InverseQ.</returns>
        private static RSAParameters GetFullPrivateParameters(BigInteger p, BigInteger q, BigInteger e, BigInteger n)
        {
            Requires.Argument(p > 0, nameof(p), "Must be positive");
            Requires.Argument(q > 0, nameof(q), "Must be positive");
            Requires.Argument(e > 0, nameof(e), "Must be positive");
            Requires.Argument(n > 0, nameof(n), "Must be positive");

            var phiOfN = n - p - q + 1; // OR: (p - 1) * (q - 1);

            var d = ModInverse(e, phiOfN);

            var dp = d % (p - 1);
            var dq = d % (q - 1);

            var qInv = ModInverse(q, p);

            return new RSAParameters
            {
                D = CryptoUtilities.CopyAndReverse(d.ToByteArray()),
                DP = CryptoUtilities.CopyAndReverse(dp.ToByteArray()),
                DQ = CryptoUtilities.CopyAndReverse(dq.ToByteArray()),
                InverseQ = CryptoUtilities.CopyAndReverse(qInv.ToByteArray()),
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

            Debug.Assert((t * a) % n == 1, "ModInverse didn't meet goal.");
            return t;
        }
#endif
    }
}
