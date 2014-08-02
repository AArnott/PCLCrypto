namespace PCLCrypto.Test.Android
{
    using System;
    using System.Globalization;
    using System.Reflection;
    using global::Android.App;
    using global::Android.Content;
    using global::Android.OS;
    using global::Android.Runtime;
    using global::Android.Views;
    using global::Android.Widget;
    using PCLCommandBase;
    using PCLCrypto.Tests;
    using PCLTesting.Runner;
    using Xamarin.Forms;
    using Xamarin.Forms.Platform.Android;
    using Resource = PCLCrypto.Tests.Android.Resource;

    [Activity(Label = "PCLCrypto.Test.Android", MainLauncher = true, Icon = "@drawable/icon")]
    public class MainActivity : AndroidActivity
    {
        protected override void OnCreate(Bundle bundle)
        {
            base.OnCreate(bundle);
            Xamarin.Forms.Forms.Init(this, bundle);

            var runner = new TestRunner(Assembly.GetExecutingAssembly());
            this.SetPage(new NavigationPage(new TestRunnerPage(runner)));
        }
    }
}
