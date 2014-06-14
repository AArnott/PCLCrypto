namespace PCLCrypto.Tests.iOS
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Reflection;
    using MonoTouch.Foundation;
    using MonoTouch.UIKit;
    using PCLTesting.Runner;
    using Xamarin.Forms;

    [Register("AppDelegate")]
    public partial class AppDelegate : UIApplicationDelegate
    {
        private UIWindow window;

        public override bool FinishedLaunching(UIApplication app, NSDictionary options)
        {
            window = new UIWindow(UIScreen.MainScreen.Bounds);
            Forms.Init();

            var runner = new TestRunner(Assembly.GetExecutingAssembly());
            window.RootViewController = new NavigationPage(new TestRunnerPage(runner)).CreateViewController();

            window.MakeKeyAndVisible();
            return true;
        }
    }
}
