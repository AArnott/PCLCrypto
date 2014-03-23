namespace PCLCrypto.Tests.iOS
{
    using System;
    using System.Collections.Generic;
    using System.Linq;

    using MonoTouch.Foundation;
    using MonoTouch.UIKit;

    [Register("AppDelegate")]
    public partial class AppDelegate : UIApplicationDelegate
    {
        private UIWindow window;
        private MyViewController viewController;

        public override bool FinishedLaunching(UIApplication app, NSDictionary options)
        {
            this.window = new UIWindow(UIScreen.MainScreen.Bounds);

            this.viewController = new MyViewController();
            this.window.RootViewController = this.viewController;

            this.window.MakeKeyAndVisible();

            return true;
        }
    }
}
