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
        Button _runTestsButton;

        TextView _resultsTextView;

        protected override void OnCreate(Bundle bundle)
        {
            base.OnCreate(bundle);

            // Set our view from the "main" layout resource
            SetContentView(Resource.Layout.Main);

            //// Get our button from the layout resource,
            //// and attach an event to it
            _runTestsButton = FindViewById<Button>(Resource.Id.RunTests);
            _runTestsButton.Click += runTestsButton_Click;

            _resultsTextView = FindViewById<TextView>(Resource.Id.ResultsTextView);
        }

        private async void runTestsButton_Click(object sender, EventArgs e)
        {
            _runTestsButton.Enabled = false;

            try
            {
                var testRunner = new TestRunner(typeof(RandomNumberGeneratorTests).Assembly);
                await testRunner.RunTestsAsync();
                _resultsTextView.Text = testRunner.Log;
            }
            catch (Exception ex)
            {
                _resultsTextView.Text = ex.ToString();
            }

            _runTestsButton.Enabled = true;
        }
    }
}

