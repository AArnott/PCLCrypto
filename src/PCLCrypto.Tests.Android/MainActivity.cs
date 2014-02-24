namespace PCLCrypto.Test.Android
{
    using System;
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
        }

        private async void RunTestsButton_Click(object sender, EventArgs e)
        {
            this.runTestsButton.Enabled = false;

            try
            {
                var testRunner = new TestRunner(typeof(RandomNumberGeneratorTests).Assembly);
                await testRunner.RunTestsAsync();
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
