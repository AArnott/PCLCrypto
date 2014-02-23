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

    public static class Crypto
    {
        public static IRandomNumberGenerator RandomNumberGenerator
        {
            get
            {
#if DESKTOP
                return new RandomNumberGenerator();
#else
                throw new NotImplementedException("Not implemented in reference assembly.");
#endif
            }
        }
    }
}
