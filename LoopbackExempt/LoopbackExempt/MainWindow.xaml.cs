using LoopbackExemptUtil;
using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace LoopbackExempt
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            this.Loaded += MainWindow_Loaded;
        }

        private LoopbackUtil loopbackUtil;
        private List<AppListItem> appListItems;

        private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            await Init();

            FilterBox.KeyUp += FilterBox_KeyUp;
            LoadingPrompt.Visibility = Visibility.Collapsed;
        }

        private Task Init()
        {
            Task task = new Task(new Action(() =>
            {
                loopbackUtil = new LoopbackUtil();

                appListItems = new List<AppListItem>();
                foreach (AppContainer appContainer in loopbackUtil.AppContainers)
                {
                    AppListItem appListItem = null;
                    Dispatcher.Invoke(new Action(() =>
                    {
                        appListItem = new AppListItem(appContainer);
                        appListItem.LoopbackChanged += AppListItem_LoopbackChanged;
                        
                    }));
                    appListItems.Add(appListItem);
                }
                appListItems.Sort((c1, c2) => c1.DisplayName.CompareTo(c2.DisplayName));
                Dispatcher.Invoke(new Action(() =>
                {
                    AppList.ItemsSource = appListItems;
                }));
            }));
            task.Start();

            return task;
        }

        CancellationTokenSource filterCancellationTokenSource;
        private async void FilterBox_KeyUp(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (filterCancellationTokenSource != null)
            {
                filterCancellationTokenSource.Cancel();
                filterCancellationTokenSource.Dispose();
            }
            filterCancellationTokenSource = new CancellationTokenSource();

            string text = ((TextBox)sender).Text.Trim().ToUpper();
            await FilterAsync(text, filterCancellationTokenSource.Token);
        }

        private Task FilterAsync(string text, CancellationToken cancellationToken)
        {
            Task task = new Task(new Action(() =>
            {
                if (text != string.Empty)
                {
                    List<AppListItem> filteredItems = new List<AppListItem>();
                    foreach (AppListItem item in appListItems)
                    {
                        if (item.DisplayName.ToUpper().Contains(text) || item.AppContainerName.ToUpper().Contains(text))
                            filteredItems.Add(item);
                    }
                    Dispatcher.Invoke(new Action(() =>
                    {
                        if (!cancellationToken.IsCancellationRequested)
                            AppList.ItemsSource = filteredItems;
                    }));
                }
                else
                {
                    Dispatcher.Invoke(new Action(() =>
                    {
                        if (!cancellationToken.IsCancellationRequested)
                            AppList.ItemsSource = appListItems;
                    }));
                }
            }), cancellationToken);
            task.Start();

            return task;
        }

        private void AppListItem_LoopbackChanged(AppContainer appContainer, bool isLoopback)
        {
            loopbackUtil.SetLoopbackExempt(appContainer, isLoopback);
            loopbackUtil.ApplyLoopbackExempt();
        }
    }
}
