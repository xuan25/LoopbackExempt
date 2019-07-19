namespace LoopbackExemptUtil
{
    /// <summary>
    /// Class <c>AppContainer</c> models a app container
    /// </summary>
    public class AppContainer
    {
        public string AppContainerName { get; internal set; }
        public string DisplayName { get; internal set; }
        public string WorkingDirectory { get; internal set; }
        public string Sid { get; internal set; }
        public bool IsLoopback { get; internal set; }

        public AppContainer(string appContainerName, string displayName, string workingDirectory, string sid, bool isLoopback)
        {
            this.AppContainerName = appContainerName;
            this.DisplayName = displayName;
            this.WorkingDirectory = workingDirectory;
            this.Sid = sid;
            this.IsLoopback = isLoopback;
        }
    }
}
