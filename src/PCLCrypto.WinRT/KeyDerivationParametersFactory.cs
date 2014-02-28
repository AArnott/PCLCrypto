//-----------------------------------------------------------------------
// <copyright file="KeyDerivationParametersFactory.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using Validation;
    using Platform = Windows.Security.Cryptography.Core;

    /// <summary>
    /// A WinRT implementation of the <see cref="IKeyDerivationParametersFactory"/> interface.
    /// </summary>
    internal class KeyDerivationParametersFactory : IKeyDerivationParametersFactory
    {
        /// <inheritdoc />
        public IKeyDerivationParameters BuildForPbkdf2(byte[] pbkdf2Salt, int iterationCount)
        {
            var parameters = Platform.KeyDerivationParameters.BuildForPbkdf2(
                pbkdf2Salt.ToBuffer(),
                (uint)iterationCount);
            return new KeyDerivationParameters(parameters);
        }

        /// <inheritdoc />
        public IKeyDerivationParameters BuildForSP800108(byte[] label, byte[] context)
        {
            Requires.NotNull(label, "label");
            Requires.NotNull(context, "context");

            var parameters = Platform.KeyDerivationParameters.BuildForSP800108(
                label.ToBuffer(),
                context.ToBuffer());
            return new KeyDerivationParameters(parameters);
        }

        /// <inheritdoc />
        public IKeyDerivationParameters BuildForSP80056a(byte[] algorithmId, byte[] partyUInfo, byte[] partyVInfo, byte[] suppPubInfo, byte[] suppPrivInfo)
        {
            Requires.NotNull(algorithmId, "algorithmId");
            Requires.NotNull(partyUInfo, "partyUInfo");
            Requires.NotNull(partyVInfo, "partyVInfo");
            Requires.NotNull(suppPubInfo, "suppPubInfo");
            Requires.NotNull(suppPrivInfo, "suppPrivInfo");

            var parameters = Platform.KeyDerivationParameters.BuildForSP80056a(
                algorithmId.ToBuffer(),
                partyUInfo.ToBuffer(),
                partyVInfo.ToBuffer(),
                suppPubInfo.ToBuffer(),
                suppPrivInfo.ToBuffer());
            return new KeyDerivationParameters(parameters);
        }
    }
}
