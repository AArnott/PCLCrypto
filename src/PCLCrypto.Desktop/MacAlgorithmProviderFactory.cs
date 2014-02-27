//-----------------------------------------------------------------------
// <copyright file="MacAlgorithmProviderFactory.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// The WinRT implementation of the <see cref="IMacAlgorithmProviderFactory"/> interface.
    /// </summary>
    internal class MacAlgorithmProviderFactory : IMacAlgorithmProviderFactory
    {
        /// <inheritdoc />
        public IMacAlgorithmProvider OpenAlgorithm(MacAlgorithm algorithm)
        {
            return new MacAlgorithmProvider(algorithm);
        }
    }
}
