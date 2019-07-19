using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;

namespace LoopbackExempt
{
    public class LoopbackUtil
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct INET_FIREWALL_AC_CAPABILITIES
        {
            public uint count;
            public IntPtr capabilities; //SID_AND_ATTRIBUTES
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct INET_FIREWALL_AC_BINARIES
        {
            public uint count;
            public IntPtr binaries;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct INET_FIREWALL_APP_CONTAINER
        {
            internal IntPtr appContainerSid;
            internal IntPtr userSid;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string appContainerName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string displayName;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string description;
            internal INET_FIREWALL_AC_CAPABILITIES capabilities;
            internal INET_FIREWALL_AC_BINARIES binaries;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string workingDirectory;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string packageFullName;
        }


        enum NETISO_FLAG
        {
            NETISO_FLAG_FORCE_COMPUTE_BINARIES = 0x1,
            NETISO_FLAG_MAX = 0x2
        }

        // Call this API to enumerate all of the AppContainers on the system 
        [DllImport("FirewallAPI.dll")]
        internal static extern uint NetworkIsolationEnumAppContainers(uint flags, out uint pdwNumPublicAppCs, out IntPtr ppPublicAppCs);

        // Call this API to free the memory returned by the Enumeration API 
        [DllImport("FirewallAPI.dll")] 
        internal static extern void NetworkIsolationFreeAppContainers(IntPtr pPublicAppCs); 
 
        // Call this API to load the current list of LoopUtil-enabled AppContainers
        [DllImport("FirewallAPI.dll")] 
        internal static extern uint NetworkIsolationGetAppContainerConfig(out uint pdwNumPublicAppCs, out IntPtr appContainerSids); 
 
        // Call this API to set the LoopUtil-exemption list 
        [DllImport("FirewallAPI.dll")]
        private static extern uint NetworkIsolationSetAppContainerConfig(uint dwNumPublicAppCs, SID_AND_ATTRIBUTES[] appContainerSids);


        // Use this API to convert a string SID into an actual SID 
        [DllImport("advapi32.dll", SetLastError=true)]
        internal static extern bool ConvertStringSidToSid(string strSid, out IntPtr pSid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);
 
        // Use this API to convert a string reference (e.g. "@{blah.pri?ms-resource://whatever}") into a plain string 
        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int SHLoadIndirectString(string pszSource, StringBuilder pszOutBuf);


        public class AppContainer
        {
            public string AppContainerName { get; set; }
            public string DisplayName { get; set; }
            public string WorkingDirectory { get; set; }
            public string Sid { get; set; }
            public bool IsLoopback { get; set; }

            public AppContainer(string appContainerName, string displayName, string workingDirectory, IntPtr intPtrSid)
            {
                this.AppContainerName = appContainerName;
                this.DisplayName = displayName;
                this.WorkingDirectory = workingDirectory;
                ConvertSidToStringSid(intPtrSid, out string sid);
                this.Sid = sid;
            }
        }

        internal List<INET_FIREWALL_APP_CONTAINER> Containers;
        public List<AppContainer> AppContainers = new List<AppContainer>();

        internal List<SID_AND_ATTRIBUTES> LoopbackContainers;
        internal HashSet<string> LoopbackContainerSids = new HashSet<string>();

        internal IntPtr _ppPublicAppCs;

        public LoopbackUtil()
        {
            Init();
        }

        public void Init()
        {
            LoopbackContainerSids.Clear();
            AppContainers.Clear();
            _ppPublicAppCs = IntPtr.Zero;
            
            //List of Apps that have LoopUtil enabled.
            LoopbackContainers = GetLoopbackContainers();
            foreach(SID_AND_ATTRIBUTES saa in LoopbackContainers)
            {
                ConvertSidToStringSid(saa.Sid, out string sid);
                LoopbackContainerSids.Add(sid);
            }

            //Full List of Apps
            Containers = GetContainers();
            foreach (INET_FIREWALL_APP_CONTAINER container in Containers)
            {
                AppContainer app = new AppContainer(container.appContainerName, container.displayName, container.workingDirectory, container.appContainerSid);
                app.IsLoopback = CheckLoopback(container.appContainerSid);
                AppContainers.Add(app);
            }
        }

        private bool CheckLoopback(IntPtr intPtr)
        {
            ConvertSidToStringSid(intPtr, out string sid);
            bool loopback = LoopbackContainerSids.Contains(sid);
            return loopback;
        }

        private static List<SID_AND_ATTRIBUTES> GetLoopbackContainers()
        {
            IntPtr arrayValue = IntPtr.Zero;
            uint count = 0;
            var list = new List<SID_AND_ATTRIBUTES>();

            // Pin down variables
            GCHandle handle_pdwCntPublicACs = GCHandle.Alloc(count, GCHandleType.Pinned);
            GCHandle handle_ppACs = GCHandle.Alloc(arrayValue, GCHandleType.Pinned);

            uint retval = NetworkIsolationGetAppContainerConfig(out count, out arrayValue);

            var structSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            for (var i = 0; i < count; i++)
            {
                var cur = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(arrayValue, typeof(SID_AND_ATTRIBUTES));
                list.Add(cur);
                arrayValue = new IntPtr((long)(arrayValue) + (long)(structSize));
            }

            //release pinned variables.
            handle_pdwCntPublicACs.Free();
            handle_ppACs.Free();

            return list;
        }

        private List<INET_FIREWALL_APP_CONTAINER> GetContainers()
        {
            List<INET_FIREWALL_APP_CONTAINER> contaners = new List<INET_FIREWALL_APP_CONTAINER>();

            uint errorCode = NetworkIsolationEnumAppContainers((int)NETISO_FLAG.NETISO_FLAG_MAX, out uint count, out IntPtr ppPublicAppCs);
            if (errorCode != 0)
                throw new ExternalException("Enum App containers failed", (int)errorCode);

            int structSize = Marshal.SizeOf(typeof(INET_FIREWALL_APP_CONTAINER));            
            for (var i = 0; i < count; i++)
            {
                INET_FIREWALL_APP_CONTAINER container = (INET_FIREWALL_APP_CONTAINER)Marshal.PtrToStructure(ppPublicAppCs + i*structSize, typeof(INET_FIREWALL_APP_CONTAINER));
                contaners.Add(container);
            }

            NetworkIsolationFreeAppContainers(ppPublicAppCs);

            return contaners;
        }

        public bool SaveLoopbackState()
        {
            var countEnabled=CountEnabledLoopUtil();
            SID_AND_ATTRIBUTES[] arr = new SID_AND_ATTRIBUTES[countEnabled];
            int count = 0;

            for (int i = 0; i < AppContainers.Count; i++)
            {
                if (AppContainers[i].IsLoopback)
                {
                    arr[count].Attributes = 0;
                    //TO DO:
                    ConvertStringSidToSid(AppContainers[i].Sid, out IntPtr ptr);
                    arr[count].Sid = ptr;
                    count++;
                }
            
            }


            if (NetworkIsolationSetAppContainerConfig((uint)countEnabled, arr) == 0)
            {
                return true;
            }
            else
            { return false; }
            
        }

        private int CountEnabledLoopUtil()
        {
            var count = 0;
            for (int i = 0; i < AppContainers.Count; i++)
            {
                if (AppContainers[i].IsLoopback)
                {
                    count++;
                }

            }
            return count;
        }
    }
}
