// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto.Tests.WindowsPhone
{
    using PCLCrypto.Tests.WindowsPhone.Resources;

    /// <summary>
    /// Provides access to string resources.
    /// </summary>
    public class LocalizedStrings
    {
        private static AppResources localizedResources = new AppResources();

        public AppResources LocalizedResources => localizedResources;
    }
}