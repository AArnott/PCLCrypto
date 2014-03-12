namespace PCLCrypto.Tests.iOS
{
    using System;
    using MonoTouch.UIKit;
    using System.Drawing;
    using PCLTesting.Infrastructure;
    using System.Globalization;

    public class MyViewController : UIViewController
    {
        private UIButton runTestsButton;
        private UITextView summaryTextView;
        private UITextView resultsTextView;
        private float buttonWidth = 200;
        private float buttonHeight = 50;

        public MyViewController()
        {
        }

        public override void ViewDidLoad()
        {
            base.ViewDidLoad();

            this.View.Frame = UIScreen.MainScreen.Bounds;
            this.View.BackgroundColor = UIColor.White;
            this.View.AutoresizingMask = UIViewAutoresizing.FlexibleWidth | UIViewAutoresizing.FlexibleHeight;

            this.summaryTextView = new UITextView();
            this.summaryTextView.Frame = new RectangleF(
                0,
                this.buttonHeight,
                this.View.Frame.Width,
                this.View.Frame.Height - this.buttonHeight * 2);
            this.resultsTextView = new UITextView();
            this.resultsTextView.Frame = new RectangleF(
                0,
                this.View.Frame.Height - this.buttonHeight,
                this.View.Frame.Width,
                this.buttonHeight);

            this.runTestsButton = UIButton.FromType(UIButtonType.RoundedRect);
            this.runTestsButton.Frame = new RectangleF(
                this.View.Frame.Width / 2 - this.buttonWidth / 2,
                0,
                this.buttonWidth,
                this.buttonHeight);

            this.runTestsButton.SetTitle("Run tests", UIControlState.Normal);

            this.runTestsButton.TouchUpInside += async (object sender, EventArgs e) =>
            {
                this.runTestsButton.SetTitle("Tests running!", UIControlState.Disabled);
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

                this.runTestsButton.SetTitle("Run tests", UIControlState.Normal);
            };

            this.runTestsButton.AutoresizingMask = 
                UIViewAutoresizing.FlexibleWidth |
                UIViewAutoresizing.FlexibleTopMargin |
                UIViewAutoresizing.FlexibleBottomMargin;

            this.View.AddSubview(this.runTestsButton);
            this.View.AddSubview(this.resultsTextView);
            this.View.AddSubview(this.summaryTextView);
        }
    }
}

