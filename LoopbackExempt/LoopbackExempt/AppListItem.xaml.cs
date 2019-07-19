using LoopbackExemptUtil;
using System.Windows;
using System.Windows.Controls;

namespace LoopbackExempt
{
    /// <summary>
    /// AppListItem.xaml 的交互逻辑
    /// </summary>
    public partial class AppListItem : UserControl
    {
        public bool IsLoopback { private set; get; }
        public string DisplayName { private set; get; }
        public string AppContainerName { private set; get; }
        public string WorkingDirectory { private set; get; }
        public string Sid { private set; get; }

        private readonly AppContainer container;

        public delegate void LoopbackChangedHandler(AppContainer appContainer, bool isLoopback);
        public event LoopbackChangedHandler LoopbackChanged;

        public AppListItem(AppContainer appContainer)
        {
            InitializeComponent();

            container = appContainer;

            Sid = container.Sid;
            DisplayName = container.DisplayName;
            AppContainerName = container.AppContainerName;
            if (container.WorkingDirectory != null)
                WorkingDirectory = container.WorkingDirectory;
            else
                WorkingDirectory = string.Empty;
            IsLoopback = container.IsLoopback;

            AppnameBox.Text = DisplayName;
            AppCkb.IsChecked = IsLoopback;

            AppCkb.Checked += AppCkb_Checked;
            AppCkb.Unchecked += AppCkb_Unchecked;
        }

        private void AppCkb_Checked(object sender, RoutedEventArgs e)
        {
            IsLoopback = true;
            LoopbackChanged?.Invoke(container, IsLoopback);
        }

        private void AppCkb_Unchecked(object sender, RoutedEventArgs e)
        {
            IsLoopback = false;
            LoopbackChanged?.Invoke(container, IsLoopback);
        }
    }
}
