// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto.Tests.WinRT.Phone
{
    using System.Reflection;
    using Xunit.Runners.UI;

    public sealed partial class App : RunnerApplication
    {
        protected override void OnInitializeRunner()
        {
            // tests can be inside the main assembly
            this.AddTestAssembly(this.GetType().GetTypeInfo().Assembly);

            // otherwise you need to ensure that the test assemblies will
            // become part of the app bundle
            ////AddTestAssembly(typeof(PortableTests).GetTypeInfo().Assembly);
        }
    }
}
