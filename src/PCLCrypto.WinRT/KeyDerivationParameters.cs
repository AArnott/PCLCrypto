// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// A WinRT implementation of the <see cref="IKeyDerivationParameters"/> interface.
    /// </summary>
    internal class KeyDerivationParameters : IKeyDerivationParameters
    {
        /// <summary>
        /// The platform parameters.
        /// </summary>
        private readonly Platform.KeyDerivationParameters platform;

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyDerivationParameters"/> class.
        /// </summary>
        /// <param name="parameters">The platform parameters.</param>
        internal KeyDerivationParameters(Platform.KeyDerivationParameters parameters)
        {
            Requires.NotNull(parameters, "parameters");

            this.platform = parameters;
        }

        /// <inheritdoc />
        public int IterationCount
        {
            get { return (int)this.platform.IterationCount; }
        }

        /// <inheritdoc />
        public byte[] KdfGenericBinary
        {
            get { return this.platform.KdfGenericBinary.ToArray(); }
            set { this.platform.KdfGenericBinary = value.ToBuffer(); }
        }

        /// <summary>
        /// Gets the platform parameters.
        /// </summary>
        /// <value>
        /// The parameters.
        /// </value>
        internal Platform.KeyDerivationParameters Parameters
        {
            get { return this.platform; }
        }
   }
}
