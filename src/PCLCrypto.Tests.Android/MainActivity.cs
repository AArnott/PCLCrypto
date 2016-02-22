// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto.Tests.Android
{
    using System;
    using System.Reflection;
    using global::Android.App;
    using global::Android.Content;
    using global::Android.OS;
    using global::Android.Runtime;
    using global::Android.Views;
    using global::Android.Widget;
    using Xunit.Runners.UI;
    using Xunit.Sdk;

    [Activity(Label = "PCLCrypto Android Runner", MainLauncher = true, Theme = "@android:style/Theme.Material.Light")]
    public class MainActivity : RunnerActivity
    {
        protected override void OnCreate(Bundle bundle)
        {
            // tests can be inside the main assembly
            this.AddTestAssembly(Assembly.GetExecutingAssembly());

            this.AddExecutionAssembly(typeof(ExtensibilityPointFactory).Assembly);

            // or in any reference assemblies
            // or in any assembly that you load (since JIT is available)
            ////AddTestAssembly(typeof(PortableTests).Assembly);

            // you can use the default or set your own custom writer (e.g. save to web site and tweet it ;-)
            ////Writer = new TcpTextWriter("10.0.1.2", 16384);

            // start running the test suites as soon as the application is loaded
            ////AutoStart = true;
            // crash the application (to ensure it's ended) and return to springboard
            ////TerminateAfterExecution = true;

            // you cannot add more assemblies once calling base
            base.OnCreate(bundle);
        }
    }
}
