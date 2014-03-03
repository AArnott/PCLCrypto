namespace PCLCrypto.Test.Android
{
    using System;
    using System.Globalization;
    using global::Android.App;
    using global::Android.Content;
    using global::Android.OS;
    using global::Android.Runtime;
    using global::Android.Views;
    using global::Android.Widget;
    using PCLCrypto.Tests;
    using PCLTesting.Infrastructure;
    using Resource = PCLCrypto.Tests.Android.Resource;

    [Activity(Label = "PCLCrypto.Test.Android", MainLauncher = true, Icon = "@drawable/icon")]
    public class MainActivity : Activity
    {
        private Button runTestsButton;

        private TextView resultsTextView;

        private TextView summaryTextView;

        protected override void OnCreate(Bundle bundle)
        {
            base.OnCreate(bundle);

            // Set our view from the "main" layout resource
            this.SetContentView(Resource.Layout.Main);

            //// Get our button from the layout resource,
            //// and attach an event to it
            this.runTestsButton = this.FindViewById<Button>(Resource.Id.RunTests);
            this.runTestsButton.Click += this.RunTestsButton_Click;

            this.resultsTextView = this.FindViewById<TextView>(Resource.Id.ResultsTextView);
            this.summaryTextView = this.FindViewById<TextView>(Resource.Id.summaryTextView);
        }

        private async void RunTestsButton_Click(object sender, EventArgs e)
        {
            this.runTestsButton.Enabled = false;

            try
            {
                var testRunner = new TestRunner(typeof(RandomNumberGeneratorTests).Assembly);
                await testRunner.RunTestsAsync();
                this.summaryTextView.Text = string.Format(
                    CultureInfo.CurrentCulture,
                    "{0}/{1} tests passed ({2}%)",
                    testRunner.PassCount,
                    testRunner.TestCount,
                    100 * testRunner.PassCount / testRunner.TestCount);
                this.resultsTextView.Text = testRunner.Log;
            }
            catch (Exception ex)
            {
                this.resultsTextView.Text = ex.ToString();
            }

            this.runTestsButton.Enabled = true;
        }
    }
}
