// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto.Tests.UWP
{
    using System.Reflection;
    using Xunit.Runners.UI;

    /// <summary>
    /// Provides application-specific behavior to supplement the default Application class.
    /// </summary>
    public sealed partial class App : RunnerApplication
    {
        protected override void OnInitializeRunner()
        {
            this.AddTestAssembly(typeof(App).GetTypeInfo().Assembly);
        }
    }
}
