using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;

namespace CaEthernet
{
    class Program
    {
        // Ethernet 1

        // using the library: https://github.com/PcapDotNet/Pcap.Net
        // to use it correctly install it from nuGet and install https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut.html

        // HELP: https://github.com/PcapDotNet/Pcap.Net/wiki

        // hier mac adressde einfügen
        static string _macSource1 = "EC:B1:D7:60:BD:8E"; //1 //141.76.83.220
        //static string _macSource2 = "C4:E9:84:00:41:2D"; //2 //172.11.4.82 //nicht genuztz

        static string macSiemens = "00:0E:8C:87:29:55";

        static string _macMulticast = "01:0E:CF:00:00:00"; // contact all

        static string TRANSACT_ID = "12345678";

        static List<Response> _collectedResponses = new List<Response>();

        static PacketDevice selectedDevice;




        static void Main(string[] args)
        {
            // Retrieve the device list from the local machine
            IList<LivePacketDevice> allDevices = LivePacketDevice.AllLocalMachine;

            if (allDevices.Count == 0)
            {
                Console.WriteLine("No interfaces found! Make sure WinPcap is installed.");
                return;
            }

            // Print the list
            for (int i = 0; i != allDevices.Count; ++i)
            {
                LivePacketDevice device = allDevices[i];
                Console.Write((i + 1) + ". " + device.Name);
                if (device.Description != null)
                    Console.WriteLine(" (" + device.Description + ")");
                else
                    Console.WriteLine(" (No description available)");
            }

            int deviceIndex = 0;
            do
            {
                Console.WriteLine("Enter the interface number (1-" + allDevices.Count + "):");
                string deviceIndexString = Console.ReadLine();
                if (!int.TryParse(deviceIndexString, out deviceIndex) ||
                    deviceIndex < 1 || deviceIndex > allDevices.Count)
                {
                    deviceIndex = 0;
                }
            } while (deviceIndex == 0);

            // Take the selected adapter
            selectedDevice = allDevices[deviceIndex - 1];

        begin:

            Console.WriteLine("Type " +
                "\n 'i' for identification request " +
                "\n 's' for send " +
                "\n 'z' for send speZial" +
                "\n 'x' to exit");
            var val = Console.ReadLine();

            if (val == "x")
                return;

            if (val == "i")
            {
                ListAllDevices();
            }

            if (val == "z")
            {
                Recive(30, IdentificationResponseHandler2);
            }

            if (val == "d")
            {
                PrintAllResponses();
                Console.WriteLine("type device to respondt to: ");
                int index = 0;
                do
                    Console.WriteLine("type in mac adress index from 0 to " + (_collectedResponses.Count - 1));
                while (!int.TryParse(Console.ReadLine(), out index) && index > 0 && index < (_collectedResponses.Count - 1));
                Sationsname(_collectedResponses[index].mac);
            }

            if (val == "p")
            {
                PrintAllResponses();
                Console.WriteLine("");
                int index = 0;
                do
                    Console.WriteLine("type in mac adress index from 0 to " + (_collectedResponses.Count - 1));
                while (!int.TryParse(Console.ReadLine(), out index) && index > 0 && index < (_collectedResponses.Count - 1));
                Get(_collectedResponses[index].mac);
            }

            //if (val == "k")
            //{
            //    if (_collectedMacs.Count <= 0)
            //        goto begin;

            //    foreach (var s in _collectedMacs)
            //    {
            //        Console.WriteLine(s);
            //    }
            //    int index = 0;
            //    do
            //        Console.WriteLine("type in mac adress index from 0 to " + (_collectedMacs.Count - 1));
            //    while (!int.TryParse(Console.ReadLine(), out index));
            //    SetRequest(index);
            //    Recive(30, SetResponseHandler);

            //}
            goto begin;
        }

        private static void Sationsname(string mac)
        {
            Console.WriteLine("neuer Stationsname: ");
            var value = Console.ReadLine();
            SendSetRequest(mac, "0203", Program.ByteArrayToHex(Encoding.ASCII.GetBytes(value)));
            Recive(30, IdentificationResponseHandler2);

        }

        private static void Get(string mac)
        {
            Console.WriteLine("value:");
            var value = Console.ReadLine();
            SendGetRequest(mac, value, "");
            Recive(30, IdentificationResponseHandler2);

        }



        private static void ListAllDevices()
        {
            SendIdentificationRequest();
            Recive(30, IdentificationResponseHandler2);
        }

        //static void IdentificationRequest()
        //{
        //    BuildAndSend(_macMulticast, "fefe", "05", "00", TRANSACT_ID, "0001", "ffff");
        //}

        static void SendIdentificationRequest()
        {
            var dcppacket = new DcpPacket();
            dcppacket.MakeIdentificationRequest();
            Send(_macMulticast, dcppacket.Build());
        }

        static void SendSetRequest(string mac, string option, string contentHex)
        {
            var dcpdata = new DcpData(option, contentHex);
            var dcppacket = new DcpPacket();
            dcppacket.MakeSetRequest(dcpdata.Build());
            Send(mac, dcppacket.Build());
        }

        static void SendGetRequest(string mac, string option, string contentHex)
        {
            var dcpdata = new DcpData(option, contentHex);
            var dcppacket = new DcpPacket();
            dcppacket.MakeGetRequest(dcpdata.Build());
            Send(mac, dcppacket.Build());
        }

        //static void SetRequest(int macindex)
        //{
        //    //74 65 73 74 31 32 33
        //    //var s = "02" + "02" + "0007" +"0000"+ "7878787878787800";
        //    //var s = "02" + "02" + "0007" + "0000" + "316531743100";
        //    var ascii = "madita-und-hannes-waren-hier";
        //    var encoded = "0000" + ByteArrayToHex(Encoding.ASCII.GetBytes(ascii));

        //    var length = ByteArrayToHex(new byte[] { (byte)(encoded.Length / 2) }).PadLeft(4, '0');

        //    if (encoded.Length % 2 == 1)
        //        encoded += "0";

        //    SetRequest(macindex, "0202" + length + encoded);
        //}

        //static void SetRequest(int macindex, string dcpDataheader)
        //{
        //    BuildAndSend(_collectedMacs[macindex], "fefd", "04", "00", TRANSACT_ID, "0000", dcpDataheader);
        //}

        //static void BuildAndSend(string macDest, string frameId, string serviceID, string serviceType, string Xid, string responseDelayFactor, string dcpDataheader)
        //{
        //    //fefe05001234567800010004ffff
        //    //fefe05001234567800010004ffff
        //    //fefe 05 00 12345678 0001 0004 ff ff
        //    string s = frameId + serviceID + serviceType + Xid + responseDelayFactor + ByteArrayToHex(new byte[] { (byte)(dcpDataheader.Length / 2) }).PadLeft(4, '0') + dcpDataheader;
        //    Send(macDest, s);
        //}

        static void Send(string macDest, byte[] content)
        {
            // Open the output device
            using (PacketCommunicator communicator = selectedDevice.Open(100, // name of the device
                                                                         PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                                                         1000)) // read timeout
            {
                communicator.SendPacket(BuildEthernetPacket(_macSource1, macDest, content));
                //communicator.SendPacket(BuildEthernetPacket(_macSource2, macDest, content));

            }
        }


        // RECIVE

        // Method for reciving packets on specified device
        static void Recive(int number, HandlePacket packetHandler)
        {
            // Open the device
            using (PacketCommunicator communicator =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                Console.WriteLine("Listening on " + selectedDevice.Description + "...");

                // start the capture
                // Callback function invoked by Pcap.Net for every incoming packet
                communicator.ReceivePackets(20, packetHandler);
            }
        }

        static void DefaultPacketHandler(Packet packet)
        {
            Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
            if (packet.Ethernet.Destination.Equals(new MacAddress(_macSource1)))
            {
                if (packet.Ethernet.Source.Equals(new MacAddress(_macSource1)))
                {
                    Console.WriteLine("sent from me to me");
                    Console.WriteLine("clear: " + Encoding.ASCII.GetString(packet.Buffer));
                    Console.WriteLine("");
                }
            }
        }

        static void IdentificationResponseHandler2(Packet packet)
        
       {
            //if (packet.Ethernet.Destination.Equals(new MacAddress(_macSource1)))
            {
                string macsource = packet.Ethernet.Source.ToString();
                string content = ByteArrayToHex(packet.Buffer);

                try
                {
                    var dcppacket = new DcpPacket(content);

                    var response = new Response()
                    {
                        mac = macsource,
                        dcpPacket = dcppacket
                    };


                    int index = _collectedResponses.FindIndex(x => x.dcpPacket._data.Equals(dcppacket._data));
                    if (index >= 0)
                    {
                        _collectedResponses[index] = response;
                    }
                    else
                    {
                        _collectedResponses.Add(response);
                    }

                }
                catch { }

                PrintAllResponses();

            }

        }

        static void PrintAllResponses()
        {
            Console.WriteLine("");
            Console.WriteLine("Awnsers: ");
            for (int i = 0; i < _collectedResponses.Count; i++)
            {
                Console.WriteLine("");
                Console.WriteLine(i + ": Adress: " + _collectedResponses[i].mac);
                //Console.WriteLine(_collectedResponses[i].dcpPacket.ToString());
                foreach (var dcpdata in _collectedResponses[i].dcpPacket.GetDcpDataPackages())
                {
                    Console.WriteLine(dcpdata.ToString());
                }
            }
        }


        //static void IdentificationResponseHandler(Packet packet)
        //{
        //    if (packet.Ethernet.Destination.Equals(new MacAddress(_macSource1)) || (packet.Ethernet.Destination.Equals(new MacAddress(_macSource2))))
        //    {
        //        string macsource = packet.Ethernet.Source.ToString();
        //        Console.WriteLine("");
        //        Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " from: " + macsource + " length:" + packet.Length);
        //        if (!_collectedMacs.Contains(packet.Ethernet.Source.ToString()))
        //            _collectedMacs.Add(packet.Ethernet.Source.ToString());

        //        string s = null;
        //        try
        //        {
        //            s = ByteArrayToHex(packet.Buffer);

        //            if (s != null)
        //            {
        //                var beginn = s.IndexOf("feff", 24);
        //                if (beginn > 0 && s.Substring(beginn + 8, 8).Equals(TRANSACT_ID))
        //                {
        //                    var transact = s.Substring(beginn + 8, 8);
        //                    var dataheader = s.Substring(beginn + 24);
        //                    // Matching Transact id.
        //                    Console.WriteLine("Matching Transaction Id found: " + transact);
        //                    Console.WriteLine("dcp-dataheader: " + dataheader);
        //                    Console.WriteLine("dcp-dataheader clear: " + Encoding.ASCII.GetString(HexToByteArray(dataheader)));
        //                    Console.WriteLine("");

        //                    Response device = new Response();
        //                    device.mac = packet.Ethernet.Source.ToString();
        //                    device.FromDcpDataPackages(dataheader);
        //                    int index = _profinetdevices.FindIndex(x => x.mac.Equals(macsource));
        //                    if (index >= 0)
        //                    {
        //                        _profinetdevices[index] = device;
        //                    }
        //                    else
        //                    {
        //                        _profinetdevices.Add(device);
        //                    }
        //                }
        //            }
        //        }
        //        catch
        //        {
        //            Console.WriteLine("unable to continue parsing");
        //        }
        //    }
        //}

        //static void SetResponseHandler(Packet packet)
        //{
        //    if (packet.Ethernet.Destination.Equals(new MacAddress(_macSource1)) || (packet.Ethernet.Destination.Equals(new MacAddress(_macSource2))))
        //    {
        //        Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " length:" + packet.Length);
        //        string s = null;
        //        try
        //        {
        //            s = ByteArrayToHex(packet.Buffer);
        //        }
        //        catch { }
        //        if (s != null)
        //        {
        //            var beginn = s.IndexOf("fefd", 24);
        //            if (beginn > 0 && s.Substring(beginn + 8, 8).Equals(TRANSACT_ID))
        //            {
        //                var transact = s.Substring(beginn + 8, 8);
        //                var datah = s.Substring(beginn + 25);
        //                // Matching Transact id.
        //                Console.WriteLine("Matching Transaction Id found: " + transact);
        //                Console.WriteLine("dcp-dataheader: " + datah);
        //                Console.WriteLine("dcp-dataheader clear: " + Encoding.ASCII.GetString(HexToByteArray(datah)));
        //                Console.WriteLine("");
        //            }
        //        }
        //    }
        //}



        // HELPERS
        public static byte[] HexToByteArray(string hex)
        {
            if (hex.Length % 2 == 1)
                hex = 0 + hex;
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static string ByteArrayToHex(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        /// <summary>
        /// This function build an Ethernet with payload packet.
        /// </summary>
        static Packet BuildEthernetPacket(string macsource, string macdest, byte[] content)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress(macsource),
                    Destination = new MacAddress(macdest),
                    EtherType = (EthernetType)34962

                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(content),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, payloadLayer);


            var pack = builder.Build(DateTime.Now);
            return pack;
        }

    }
}
