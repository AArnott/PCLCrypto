// Copyright (c) Andrew Arnott. All rights reserved.
// Licensed under the Microsoft Public License (Ms-PL) license. See LICENSE file in the project root for full license information.

namespace PCLCrypto.Tests.iOS
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;
    using Xunit.Runner;
    using Xunit.Sdk;

#if __UNIFIED__
    using Foundation;
    using UIKit;
#else
    using MonoTouch.Foundation;
    using MonoTouch.UIKit;
#endif

    // The UIApplicationDelegate for the application. This class is responsible for launching the
    // User Interface of the application, as well as listening (and optionally responding) to
    // application events from iOS.
    [Register("AppDelegate")]
    public partial class AppDelegate : RunnerAppDelegate
    {
        // This method is invoked when the application has loaded and is ready to run. In this
        // method you should instantiate the window, load the UI into it and then make the window
        // visible.
        //
        // You have 17 seconds to return from this method, or iOS will terminate your application.
        public override bool FinishedLaunching(UIApplication app, NSDictionary options)
        {
            // We need this to ensure the execution assembly is part of the app bundle
            this.AddExecutionAssembly(typeof(ExtensibilityPointFactory).Assembly);
            this.AddExecutionAssembly(typeof(SkippableFactDiscoverer).Assembly);

            // tests can be inside the main assembly
            this.AddTestAssembly(Assembly.GetExecutingAssembly());

            // otherwise you need to ensure that the test assemblies will
            // become part of the app bundle
            ////this.AddTestAssembly(typeof(PortableTests).Assembly);

            // You can use the default or set your own custom writer (e.g. save to web site and tweet it ;-)
            // Wire up a server with `nc -l 4444` on the Mac hosting the emulator to log to the terminal window.
            ////Writer = new TcpTextWriter("10.0.0.47", 4444);

            // start running the test suites as soon as the application is loaded
            this.AutoStart = true;

            // crash the application (to ensure it's ended) and return to springboard
            ////this.TerminateAfterExecution = true;

            return base.FinishedLaunching(app, options);
        }
    }
}