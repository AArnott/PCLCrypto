//-----------------------------------------------------------------------
// <copyright file="Crypto.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// Offers access to platform-specific cryptographic functionality.
    /// </summary>
    public static class Crypto
    {
        /// <summary>
        /// Gets a cryptographically strong random number generator.
        /// </summary>
        public static IRandomNumberGenerator RandomNumberGenerator
        {
            get
            {
#if PCL
                throw new NotImplementedException("Not implemented in reference assembly.");
#else
                return new RandomNumberGenerator();
#endif
            }
        }
    }
}
