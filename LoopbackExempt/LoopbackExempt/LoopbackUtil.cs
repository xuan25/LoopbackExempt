using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace LoopbackExemptUtil
{
    public class LoopbackUtil
    {

        #region Structures

        [StructLayout(LayoutKind.Sequential)]
        private struct SidAndAttributes
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct InetFirewallAcCapabilities
        {
            public uint count;
            public IntPtr capabilities;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct InetFirewallAcBinaries
        {
            public uint count;
            public IntPtr binaries;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct InetFirewallAppContainer
        {
            public IntPtr appContainerSid;
            public IntPtr userSid;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string appContainerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string displayName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string description;
            public InetFirewallAcCapabilities capabilities;
            public InetFirewallAcBinaries binaries;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string workingDirectory;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string packageFullName;
        }

        #endregion

        #region Apis

        private enum NetisoFlag
        {
            NetisoFlagForceComputeBinaries = 0x1,
            NetisoFlagMax = 0x2
        }

        [DllImport("FirewallAPI.dll")]
        private static extern uint NetworkIsolationEnumAppContainers(uint flags, out uint pdwNumPublicAppCs, out IntPtr ppPublicAppCs);

        [DllImport("FirewallAPI.dll")]
        private static extern void NetworkIsolationFreeAppContainers(IntPtr pPublicAppCs); 
 
        [DllImport("FirewallAPI.dll")]
        private static extern uint NetworkIsolationGetAppContainerConfig(out uint pdwNumPublicAppCs, out IntPtr appContainerSids); 
 
        [DllImport("FirewallAPI.dll")]
        private static extern uint NetworkIsolationSetAppContainerConfig(uint dwNumPublicAppCs, SidAndAttributes[] appContainerSids);

        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool ConvertStringSidToSid(string strSid, out IntPtr pSid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
 
        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern int SHLoadIndirectString(string pszSource, StringBuilder pszOutBuf, uint cchOutBuf, IntPtr ppvReserved);

        #endregion

        #region Public property

        public List<AppContainer> AppContainers { get; set; }

        #endregion

        #region Private fields

        private HashSet<string> loopbackSids;

        #endregion

        #region Constructor

        public LoopbackUtil()
        {
            Init();
        }

        #endregion

        #region Public methods

        public void SetLoopbackExempt(AppContainer appContainer, bool flag)
        {
            appContainer.IsLoopback = flag;

            bool success;
            if (flag)
                success = loopbackSids.Add(appContainer.Sid);
            else
                success = loopbackSids.Remove(appContainer.Sid);

            if (!success)
                throw new InvalidOperationException("App sid conflict");
        }

        public void ApplyLoopbackExempt()
        {
            int count = loopbackSids.Count;

            List<SidAndAttributes> list = new List<SidAndAttributes>();
            foreach(string sid in loopbackSids)
            {
                ConvertStringSidToSid(sid, out IntPtr pSid);
                SidAndAttributes sdiAndAttributes = new SidAndAttributes();
                sdiAndAttributes.Sid = pSid;
                sdiAndAttributes.Attributes = 0;
                list.Add(sdiAndAttributes);
            }

            uint code = NetworkIsolationSetAppContainerConfig((uint)count, list.ToArray());
            if (code != 0)
                throw new ExternalException("Set config failed", (int)code);

        }

        #endregion

        #region Private methods

        private void Init()
        {
            // User sid
            WindowsIdentity currentUser = WindowsIdentity.GetCurrent();
            string userSid = currentUser.User.ToString();

            // Loopback set
            SidAndAttributes[] LoopbackContainers = GetLoopbackContainers();
            loopbackSids = new HashSet<string>();
            foreach (SidAndAttributes sdiAndAttributes in LoopbackContainers)
            {
                ConvertSidToStringSid(sdiAndAttributes.Sid, out string sid);
                loopbackSids.Add(sid);
            }

            // User App list
            AppContainers = new List<AppContainer>();
            InetFirewallAppContainer[] containers = GetContainers();
            foreach (InetFirewallAppContainer container in containers)
            {
                ConvertSidToStringSid(container.userSid, out string appUserSid);
                if (userSid == appUserSid)
                {
                    // Display name
                    string displayName = container.displayName;
                    if (displayName.StartsWith("@"))
                    {
                        StringBuilder stringBuilder = new StringBuilder(2048);
                        int code = SHLoadIndirectString(displayName, stringBuilder, (uint)stringBuilder.Capacity, IntPtr.Zero);
                        string name = stringBuilder.ToString();
                        if (code == 0 && name.Length > 0)
                            displayName = name;
                    }
                    // Sid
                    ConvertSidToStringSid(container.appContainerSid, out string sid);
                    // Loopback
                    bool isLoopback = CheckLoopback(container.appContainerSid);

                    AppContainer app = new AppContainer(container.appContainerName, displayName, container.workingDirectory, sid, isLoopback);
                    AppContainers.Add(app);
                }
            }
        }

        private static SidAndAttributes[] GetLoopbackContainers()
        {
            uint errorCode = NetworkIsolationGetAppContainerConfig(out uint count, out IntPtr appContainerSids);
            if (errorCode != 0)
                throw new ExternalException("Enum loopback containers failed", (int)errorCode);

            SidAndAttributes[] sdiAndAttributes = new SidAndAttributes[count];
            int structSize = Marshal.SizeOf(typeof(SidAndAttributes));

            for (var i = 0; i < count; i++)
                sdiAndAttributes[i] = (SidAndAttributes)Marshal.PtrToStructure(appContainerSids + i * structSize, typeof(SidAndAttributes));

            return sdiAndAttributes;
        }

        private InetFirewallAppContainer[] GetContainers()
        {
            uint errorCode = NetworkIsolationEnumAppContainers((int)NetisoFlag.NetisoFlagMax, out uint count, out IntPtr ppPublicAppCs);
            if (errorCode != 0)
                throw new ExternalException("Enum App containers failed", (int)errorCode);

            InetFirewallAppContainer[] containers = new InetFirewallAppContainer[count];
            int structSize = Marshal.SizeOf(typeof(InetFirewallAppContainer));

            for (var i = 0; i < count; i++)
                containers[i] = (InetFirewallAppContainer)Marshal.PtrToStructure(ppPublicAppCs + i * structSize, typeof(InetFirewallAppContainer));

            NetworkIsolationFreeAppContainers(ppPublicAppCs);

            return containers;
        }

        private bool CheckLoopback(IntPtr intPtr)
        {
            ConvertSidToStringSid(intPtr, out string sid);
            bool loopback = loopbackSids.Contains(sid);
            return loopback;
        }

        #endregion

    }
}
