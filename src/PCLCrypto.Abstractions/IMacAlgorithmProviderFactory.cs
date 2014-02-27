//-----------------------------------------------------------------------
// <copyright file="IMacAlgorithmProviderFactory.cs" company="Andrew Arnott">
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
    /// A factory for <see cref="IMacAlgorithmProvider"/> instances.
    /// </summary>
    public interface IMacAlgorithmProviderFactory
    {
        /// <summary>
        /// Gets a MAC provider for the given algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>An instance of <see cref="IMacAlgorithmProvider"/>.</returns>
        IMacAlgorithmProvider OpenAlgorithm(MacAlgorithm algorithm);
    }
}
