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
    using PCLCommandBase;
    using PCLCrypto.Tests;
    using PCLTesting.Infrastructure;
    using Resource = PCLCrypto.Tests.Android.Resource;

    [Activity(Label = "PCLCrypto.Test.Android", MainLauncher = true, Icon = "@drawable/icon")]
    public class MainActivity : Activity
    {
        private TestRunner runner;

        private TestRunnerViewModel viewModel;

        protected override void OnCreate(Bundle bundle)
        {
            base.OnCreate(bundle);

            // Set our view from the "main" layout resource
            this.SetContentView(Resource.Layout.Main);

            this.runner = new TestRunner(typeof(RandomNumberGeneratorTests).Assembly);
            this.viewModel = new TestRunnerViewModel(this.runner);

            // Get our button from the layout resource,
            // and attach an event to it
            var runTestsButton = this.FindViewById<Button>(Resource.Id.RunTests);
            var resultsTextView = this.FindViewById<TextView>(Resource.Id.ResultsTextView);
            var summaryTextView = this.FindViewById<TextView>(Resource.Id.summaryTextView);
            var progressBar = this.FindViewById<ProgressBar>(Resource.Id.progressBar1);

            runTestsButton.Click += (s, e) =>
            {
                if (this.viewModel.StartCommand.CanExecute(null))
                {
                    this.viewModel.StartCommand.Execute(null);
                }
                else
                {
                    this.viewModel.StopCommand.Execute(null);
                }
            };

            this.viewModel.PropertyChanged += (s, e) =>
            {
                switch (e.PropertyName)
                {
                    case "IsRunning":
                        runTestsButton.Text = this.viewModel.IsRunning ? "Abort" : "Run Tests";
                        progressBar.Visibility = this.viewModel.IsRunning ? ViewStates.Visible : ViewStates.Gone;
                        break;
                    case "CurrentProgress":
                        progressBar.Max = this.viewModel.CurrentProgress.TestCount;
                        progressBar.Progress = this.viewModel.CurrentProgress.ExecuteCount;
                        break;
                    case "Log":
                        resultsTextView.Text = this.viewModel.Log;
                        break;
                    case "Summary":
                        summaryTextView.Text = this.viewModel.Summary;
                        break;
                }
            };

            this.viewModel.StartCommand.Execute(null);
        }
    }
}
