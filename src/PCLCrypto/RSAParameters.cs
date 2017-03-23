// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Represents the standard parameters for the RSA algorithm.
    /// </summary>
    /// <remarks>
    /// All integers are encoded in big endian.
    /// </remarks>
    public struct RSAParameters
    {
        /// <summary>
        /// Represents the private exponent parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] D;

        /// <summary>
        /// Represents the exponent1 parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] DP;

        /// <summary>
        /// Represents the exponent2 parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] DQ;

        /// <summary>
        /// Represents the publicExponent parameter for the System.Security.Cryptography.RSA
        /// algorithm.
        /// </summary>
        public byte[] Exponent;

        /// <summary>
        /// Represents the coefficient parameter for the System.Security.Cryptography.RSA
        /// algorithm.
        /// </summary>
        public byte[] InverseQ;

        /// <summary>
        /// Represents the modulus parameter for the System.Security.Cryptography.RSA
        /// algorithm.
        /// </summary>
        public byte[] Modulus;

        /// <summary>
        /// Represents the prime1 parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] P;

        /// <summary>
        /// Represents the prime2 parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] Q;
    }
}
