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
    public struct RSAParameters
    {
        /// <summary>
        /// Represents the D parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] D;

        /// <summary>
        /// Represents the DP parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] DP;

        /// <summary>
        /// Represents the DQ parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] DQ;

        /// <summary>
        /// Represents the Exponent parameter for the System.Security.Cryptography.RSA
        /// algorithm.
        /// </summary>
        public byte[] Exponent;

        /// <summary>
        /// Represents the InverseQ parameter for the System.Security.Cryptography.RSA
        /// algorithm.
        /// </summary>
        public byte[] InverseQ;

        /// <summary>
        /// Represents the Modulus parameter for the System.Security.Cryptography.RSA
        /// algorithm.
        /// </summary>
        public byte[] Modulus;

        /// <summary>
        /// Represents the P parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] P;

        /// <summary>
        /// Represents the Q parameter for the System.Security.Cryptography.RSA algorithm.
        /// </summary>
        public byte[] Q;
    }
}
