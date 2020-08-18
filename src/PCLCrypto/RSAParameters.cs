// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;

#pragma warning disable CA1051 // Do not declare visible instance fields

    /// <summary>
    /// Represents the standard parameters for the RSA algorithm.
    /// </summary>
    /// <remarks>
    /// All integers are encoded in big endian.
    /// </remarks>
    public struct RSAParameters : IEquatable<RSAParameters>
    {
        /// <summary>
        /// Represents the private exponent parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[]? D;

        /// <summary>
        /// Represents the exponent1 parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[]? DP;

        /// <summary>
        /// Represents the exponent2 parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[]? DQ;

        /// <summary>
        /// Represents the publicExponent parameter for the System.Security.Cryptography.RSA
        /// algorithm.
        /// </summary>
        public byte[]? Exponent;

        /// <summary>
        /// Represents the coefficient parameter for the System.Security.Cryptography.RSA
        /// algorithm.
        /// </summary>
        public byte[]? InverseQ;

        /// <summary>
        /// Represents the modulus parameter for the System.Security.Cryptography.RSA
        /// algorithm.
        /// </summary>
        public byte[]? Modulus;

        /// <summary>
        /// Represents the prime1 parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[]? P;

        /// <summary>
        /// Represents the prime2 parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[]? Q;

        /// <summary>
        /// Checks value equality between two <see cref="RSAParameters"/> values.
        /// </summary>
        /// <param name="first">One value to compare.</param>
        /// <param name="second">Another value to compare.</param>
        /// <returns><c>true</c> if the values are equal; <c>false</c> otherwise.</returns>
        public static bool operator ==(RSAParameters first, RSAParameters second) => first.Equals(second);

        /// <summary>
        /// Checks value inequality between two <see cref="RSAParameters"/> values.
        /// </summary>
        /// <param name="first">One value to compare.</param>
        /// <param name="second">Another value to compare.</param>
        /// <returns><c>false</c> if the values are equal; <c>true</c> otherwise.</returns>
        public static bool operator !=(RSAParameters first, RSAParameters second) => !first.Equals(second);

        /// <inheritdoc/>
        public override bool Equals(object obj) => obj is RSAParameters other && this.Equals(other);

        /// <inheritdoc/>
        public override int GetHashCode() => GetHashCode(this.Modulus.AsSpan());

        /// <inheritdoc/>
        public bool Equals(RSAParameters other)
        {
            return Equals(this.D.AsSpan(), other.D.AsSpan())
                && Equals(this.DP.AsSpan(), other.DP.AsSpan())
                && Equals(this.DQ.AsSpan(), other.DQ.AsSpan())
                && Equals(this.Exponent.AsSpan(), other.Exponent.AsSpan())
                && Equals(this.InverseQ.AsSpan(), other.InverseQ.AsSpan())
                && Equals(this.Modulus.AsSpan(), other.Modulus.AsSpan())
                && Equals(this.P.AsSpan(), other.P.AsSpan())
                && Equals(this.Q.AsSpan(), other.Q.AsSpan());
        }

        private static bool Equals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            for (int i = 0; i < a.Length; i++)
            {
                if (a[i] != b[i])
                {
                    return false;
                }
            }

            return true;
        }

        private static int GetHashCode(ReadOnlySpan<byte> span)
        {
            unchecked
            {
                int hash = 0;
                for (int i = 0; i < span.Length; i++)
                {
                    hash += span[i];
                }

                return hash;
            }
        }
    }
}
