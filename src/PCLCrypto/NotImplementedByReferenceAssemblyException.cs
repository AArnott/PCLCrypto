// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

#if NETSTANDARD2_0

namespace PCLCrypto
{
    using System;

    /// <summary>
    /// An exception thrown from the PCLCrypto reference assembly when it is called
    /// instead of a platform-specific assembly at runtime.
    /// </summary>
#pragma warning disable CA1032 // Implement standard exception constructors
    internal class NotImplementedByReferenceAssemblyException : NotImplementedException
#pragma warning restore CA1032 // Implement standard exception constructors
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NotImplementedByReferenceAssemblyException"/> class.
        /// </summary>
        internal NotImplementedByReferenceAssemblyException()
            : base("This is a reference assembly and does not contain implementation. Be sure to install the PCLCrypto package into your application so the platform implementation assembly will be used at runtime.")
        {
        }
    }
}

#endif
