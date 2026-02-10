using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Timers;

namespace SecureYourWifi
{
    public partial class Service1 : ServiceBase
    {
        Timer timer = new Timer(); // name space(using System.Timers;)

        // WLAN API Constants
        private const uint WLAN_API_VERSION = 2;
        private const uint WLAN_AVAILABLE_NETWORK_CONNECTED = 1;

        // P/Invoke declarations for WLAN API
        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern uint WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern uint WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern uint WlanGetAvailableNetworkList(IntPtr hClientHandle, Guid interfaceGuid, uint dwFlags, IntPtr pReserved, out IntPtr ppAvailableNetworkList);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern uint WlanDisconnect(IntPtr hClientHandle, ref Guid interfaceGuid, IntPtr pReserved);

        [DllImport("wlanapi.dll", SetLastError = true)]
        private static extern void WlanFreeMemory(IntPtr pMemory);

        // Enums and Structs
        private enum DOT11_AUTH_ALGORITHM : uint
        {
            DOT11_AUTH_ALGO_80211_OPEN = 1,
            DOT11_AUTH_ALGO_80211_SHARED_KEY = 2
        }

        private enum DOT11_CIPHER_ALGORITHM : uint
        {
            DOT11_CIPHER_ALGO_NONE = 0,
            DOT11_CIPHER_ALGO_WEP40 = 1,
            DOT11_CIPHER_ALGO_TKIP = 2,
            DOT11_CIPHER_ALGO_CCMP = 4,
            DOT11_CIPHER_ALGO_WEP104 = 5
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WLAN_INTERFACE_INFO_LIST
        {
            public uint dwNumberOfItems;
            public uint dwIndex;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public WLAN_INTERFACE_INFO[] InterfaceInfo;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WLAN_INTERFACE_INFO
        {
            public Guid InterfaceGuid;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
            public string strInterfaceDescription;
            public uint isState;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WLAN_AVAILABLE_NETWORK_LIST
        {
            public uint dwNumberOfItems;
            public uint dwIndex;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public WLAN_AVAILABLE_NETWORK[] Network;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WLAN_AVAILABLE_NETWORK
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string strProfileName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)]
            public byte[] dot11Ssid;
            public uint dot11BssPhyType;
            public int iNetworkConnectable;
            public uint wlanNotConnectableReason;
            public uint uNumberofBssids;
            public int bMorePhyTypes;
            public DOT11_AUTH_ALGORITHM dot11DefaultAuthAlgorithm;
            public DOT11_CIPHER_ALGORITHM dot11DefaultCipherAlgorithm;
            public uint dwFlags;
            public uint dwReserved;
        }

        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            WriteToFile("Service is started at " + DateTime.Now);
            timer.Elapsed += new ElapsedEventHandler(OnElapsedTime);
            timer.Interval = 5000; //number in milisecinds
            timer.Enabled = true;
        }

        protected override void OnStop()
        {
            WriteToFile("Service is stopped at " + DateTime.Now);
            timer.Enabled = false;
        }

        private void OnElapsedTime(object source, ElapsedEventArgs e)
        {
            try
            {
                DisconnectUnsecuredNetworks();
            }
            catch (Exception ex)
            {
                WriteToFile("Error in OnElapsedTime: " + ex.Message);
            }
        }

        private void DisconnectUnsecuredNetworks()
        {
            uint negotiatedVersion;
            IntPtr clientHandle = IntPtr.Zero;
            IntPtr interfaceListPtr = IntPtr.Zero;
            IntPtr networkListPtr = IntPtr.Zero;

            try
            {
                // Open WLAN handle
                uint result = WlanOpenHandle(WLAN_API_VERSION, IntPtr.Zero, out negotiatedVersion, out clientHandle);
                if (result != 0)
                {
                    WriteToFile("Failed to open WLAN handle: " + result);
                    return;
                }

                // Enumerate wireless interfaces
                result = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out interfaceListPtr);
                if (result != 0)
                {
                    WriteToFile("Failed to enumerate WLAN interfaces: " + result);
                    return;
                }

                WLAN_INTERFACE_INFO_LIST interfaceList = Marshal.PtrToStructure<WLAN_INTERFACE_INFO_LIST>(interfaceListPtr);
                
                for (int i = 0; i < interfaceList.dwNumberOfItems; i++)
                {
                    IntPtr interfacePtr = new IntPtr(interfaceListPtr.ToInt64() + Marshal.SizeOf(typeof(uint)) * 2 + Marshal.SizeOf(typeof(WLAN_INTERFACE_INFO)) * i);
                    WLAN_INTERFACE_INFO wlanInterface = Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(interfacePtr);

                    // Get available networks for this interface
                    result = WlanGetAvailableNetworkList(clientHandle, wlanInterface.InterfaceGuid, 0, IntPtr.Zero, out networkListPtr);
                    if (result == 0)
                    {
                        WLAN_AVAILABLE_NETWORK_LIST networkList = Marshal.PtrToStructure<WLAN_AVAILABLE_NETWORK_LIST>(networkListPtr);

                        for (int j = 0; j < networkList.dwNumberOfItems; j++)
                        {
                            IntPtr networkPtr = new IntPtr(networkListPtr.ToInt64() + Marshal.SizeOf(typeof(uint)) * 2 + Marshal.SizeOf(typeof(WLAN_AVAILABLE_NETWORK)) * j);
                            WLAN_AVAILABLE_NETWORK network = Marshal.PtrToStructure<WLAN_AVAILABLE_NETWORK>(networkPtr);

                            // Check if network is open (no security)
                            if (network.dot11DefaultAuthAlgorithm == DOT11_AUTH_ALGORITHM.DOT11_AUTH_ALGO_80211_OPEN &&
                                network.dot11DefaultCipherAlgorithm == DOT11_CIPHER_ALGORITHM.DOT11_CIPHER_ALGO_NONE)
                            {
                                // If connected, disconnect
                                if ((network.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED) != 0)
                                {
                                    result = WlanDisconnect(clientHandle, ref wlanInterface.InterfaceGuid, IntPtr.Zero);
                                    WriteToFile("Disconnected from unsecured network at " + DateTime.Now + ". Status: " + result);
                                }
                            }
                        }

                        WlanFreeMemory(networkListPtr);
                        networkListPtr = IntPtr.Zero;
                    }
                }
            }
            catch (Exception ex)
            {
                WriteToFile("Exception in DisconnectUnsecuredNetworks: " + ex.Message);
            }
            finally
            {
                if (interfaceListPtr != IntPtr.Zero)
                    WlanFreeMemory(interfaceListPtr);
                if (networkListPtr != IntPtr.Zero)
                    WlanFreeMemory(networkListPtr);
                if (clientHandle != IntPtr.Zero)
                    WlanCloseHandle(clientHandle, IntPtr.Zero);
            }
        }

        public void WriteToFile(string Message)
        {
            string path = AppDomain.CurrentDomain.BaseDirectory + "\\Logs";
            if (!Directory.Exists(path))
            {
                Directory.CreateDirectory(path);
            }
            string filepath = AppDomain.CurrentDomain.BaseDirectory + "\\Logs\\ServiceLog_" + DateTime.Now.Date.ToShortDateString().Replace('/', '_') + ".txt";
            if (!File.Exists(filepath))
            {
                // Create a file to write to.
                using (StreamWriter sw = File.CreateText(filepath))
                {
                    sw.WriteLine(Message);
                }
            }
            else
            {
                using (StreamWriter sw = File.AppendText(filepath))
                {
                    sw.WriteLine(Message);
                }
            }
        }
    }
}