﻿using System;
using System.Collections.Generic;
using System.Linq;

using System.Text;
using System.Threading;
using PcapDotNet.Core;
using PcapDotNet.Packets;
using PcapDotNet.Packets.Ethernet;
using PcapDotNet.Packets.IpV4;
using PcapDotNet.Packets.Transport;

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
        static string _ipSource1 = "172.16.4.101"; //"141.76.83.220";
        //static string _macSource2 = "C4:E9:84:00:41:2D"; //2 //172.11.4.82 //nicht genuztz

        static string _macMulticast = "01:0E:CF:00:00:00"; // contact all

        static string TRANSACT_ID = "12345678";

        static List<Response> _collectedResponses = new List<Response>();

        static PacketDevice selectedDevice;

        static PacketCommunicator communicator;
        static PacketCommunicator communicatorReciver;



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


            communicator = selectedDevice.Open(100, // name of the device
                                            PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                            1000); // read timeout

            communicatorReciver = selectedDevice.Open(100, // name of the device
                                            PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                            1000); // read timeout

            Thread t = new Thread(() => { communicatorReciver.ReceivePackets(5000, UDPDefaultHandler); });
            t.Start();


        begin:

            Console.WriteLine("\n\n Type " +
                "\n 'i' >> to begin << and send a identification request to all decices" +
                "\n 'set name' sets name of listed device " +
                //"\n 'z' for set name to custom mac " +
                "\n 'set ip' sets ip and subnet of listed device " +
                "\n 'read filter' get filter data from listed 'IO-Device' " +
                "\n 'read 0' get I&M 0 data from listed 'IO-Device' " +
                "\n 'read 1' get I&M 1 data from listed 'IO-Device' " +
                "\n 'write 1' set I&M 1 data from listed 'IO-Device' " +
                //"\n 'u' rpc " +
                //"\n 'a' rpc to all" +
                "\n 'x' to exit");
            var val = Console.ReadLine();

            if (val == "x")
                return;

            if (val == "i")
            {
                ListAllDevices();
            }

            if (val == "set name")
            {
                try
                {
                    PrintAllResponses();
                    Console.WriteLine("select device, which name should be changed: ");
                    int index = 0;
                    do
                        Console.WriteLine("type in mac adress index from 0 to " + (_collectedResponses.Count - 1));
                    while (!int.TryParse(Console.ReadLine(), out index) && index > 0 && index < (_collectedResponses.Count - 1));
                    Sationsname(_collectedResponses[index].mac);
                }
                catch (Exception ex)
                { LowlightConsole(ex.Message); }
            }

            if (val == "set ip")
            {
                try
                {
                    PrintAllResponses();
                    Console.WriteLine("select device, which ip should be changed: ");
                    int index = 0;
                    do
                        Console.WriteLine("type in mac adress index from 0 to " + (_collectedResponses.Count - 1));
                    while (!int.TryParse(Console.ReadLine(), out index) && index > 0 && index < (_collectedResponses.Count - 1));
                    Sationsip(_collectedResponses[index].mac);
                }
                catch (Exception ex)
                { LowlightConsole(ex.Message); }
            }

            if (val == "read filter")
            {
                try
                {
                    PrintAllResponses();
                    Console.WriteLine("select device, which rpc I&M 0 FILTER Data should be read ");
                    int index = 0;
                    do
                        Console.WriteLine("type in device index from 0 to " + (_collectedResponses.Count - 1));
                    while (!int.TryParse(Console.ReadLine(), out index) && index > 0 && index < (_collectedResponses.Count - 1));
                    RcpReadFilter(index);
                }
                catch (Exception ex)
                { LowlightConsole(ex.Message); }
            }

            if (val == "read 0")
            {
                try
                {
                    PrintAllResponses();
                    Console.WriteLine("select device, which rpc I&M 0 Data should be read ");
                    int index = 0;
                    do
                        Console.WriteLine("type in device index from 0 to " + (_collectedResponses.Count - 1));
                    while (!int.TryParse(Console.ReadLine(), out index) && index > 0 && index < (_collectedResponses.Count - 1));
                    RcpReadIandM0(index);
                }
                catch (Exception ex)
                { LowlightConsole(ex.Message); }
            }

            if (val == "read 1")
            {
                try
                {
                    PrintAllResponses();
                    Console.WriteLine("select device, which rpc I&M 1 Data should be read ");
                    int index = 0;
                    do
                        Console.WriteLine("type in device index from 0 to " + (_collectedResponses.Count - 1));
                    while (!int.TryParse(Console.ReadLine(), out index) && index > 0 && index < (_collectedResponses.Count - 1));
                    RcpReadIandM1(index);
                }
                catch (Exception ex)
                { LowlightConsole(ex.Message); }
            }

            if (val == "write 1")
            {
                try
                {
                    PrintAllResponses();
                    Console.WriteLine("select device, which rpc I&M 1 Data should be written to");
                    int index = 0;
                    do
                        Console.WriteLine("type in device index from 0 to " + (_collectedResponses.Count - 1));
                    while (!int.TryParse(Console.ReadLine(), out index) && index > 0 && index < (_collectedResponses.Count - 1));
                    RcpWriteIandM1(index);
                }
                catch (Exception ex)
                { LowlightConsole(ex.Message); }
            }

            goto begin;
        }

        private static void ListAllDevices()
        {
            var t = new Thread(() => { Recive(40, IdentificationResponseHandler); });
            t.Start();
            SendIdentificationRequest();
        }

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
            var hex = dcppacket.Build();
            Send(mac, hex);
        }

        private static void Sationsname(string mac)
        {
            Console.WriteLine("neuer Stationsname: ");
            var value = Console.ReadLine();
            var t = new Thread(() =>
            {
                var t = new Thread(() => { Recive(30, DefaultPacketHandler); });
                t.Start();
                SendSetRequest(mac, "0202", value.StringToHex());
            });
            t.Start();
        }

        private static void Sationsip(string mac)
        {
            Console.WriteLine("neue ip: ");
            var value0 = Console.ReadLine();
            IpV4Address ip4 = new IpV4Address(value0);
            var i = ip4.ToValue().ToString("X");
            var g = ip4.ToValue().ToString("X");
            Console.WriteLine("neue gateway: " + value0);

            Console.WriteLine("neue subnetz: ");
            var value1 = Console.ReadLine();
            IpV4Address ipsubnetz = new IpV4Address(value1);
            var s = ipsubnetz.ToValue().ToString("X");

            var t = new Thread(() => { Recive(30, DefaultPacketHandler); });
            t.Start();
            SendSetRequest(mac, "0102",i + s +g);
        }

        private static void RcpReadFilter(int index)
        {
            string ip = "";
            string uuid = "";
            foreach (var dcpdata in _collectedResponses[index].dcpPacket.GetDcpDataPackages())
            {
                if (dcpdata.ip() != "")
                {
                    ip = dcpdata.ip();
                }
                if (dcpdata.ToGuid() != Guid.Empty)
                {
                    uuid = dcpdata.ToGuid().ToString();
                }
            }
            Console.WriteLine("connecting: " + _collectedResponses[index].mac);

            BuilderClass.seqnr = 0;
            BuilderClass.rpc_seqnr = 0;

            Send(_collectedResponses[index].mac, ip, ImplicitReadReq(uuid, BuilderClass.index_im0filter, "00 00", "00 00", BuilderClass.rpc_activity_uuid_imf));
        }

        private static void RcpReadIandM0(int index)
        {
            string ip = "";
            string uuid = "";
            foreach (var dcpdata in _collectedResponses[index].dcpPacket.GetDcpDataPackages())
            {
                if (dcpdata.ip() != "")
                {
                    ip = dcpdata.ip();
                }
                if (dcpdata.ToGuid() != Guid.Empty)
                {
                    uuid = dcpdata.ToGuid().ToString();
                }
            }
            Console.WriteLine("slot: ");
            var slot2 = Console.ReadLine().PadLeft(4, '0');
            Console.WriteLine("sub slot: ");
            var subslot2 = Console.ReadLine().PadLeft(4, '0');

            BuilderClass.seqnr = 0;
            BuilderClass.rpc_seqnr = 0;

            Send(_collectedResponses[index].mac, ip, ImplicitReadReq(uuid, BuilderClass.index_im0, slot2, subslot2, BuilderClass.rpc_activity_uuid3));
        }

        private static void RcpReadIandM1(int index)
        {
            string ip = "";
            string uuid = "";
            foreach (var dcpdata in _collectedResponses[index].dcpPacket.GetDcpDataPackages())
            {
                if (dcpdata.ip() != "")
                {
                    ip = dcpdata.ip();
                }
                if (dcpdata.ToGuid() != Guid.Empty)
                {
                    uuid = dcpdata.ToGuid().ToString();
                }
            }
            Console.WriteLine("slot: 0");
            Console.WriteLine("sub slot: 1");
            Console.ReadLine();

            BuilderClass.seqnr = 0;
            BuilderClass.rpc_seqnr = 0;

            Send(_collectedResponses[index].mac, ip, ImplicitReadReq(uuid, BuilderClass.index_im1, "00 00", "00 01", BuilderClass.rpc_activity_uuid_im1r));
        }



        private static void RcpWriteIandM1(int index)
        {
            string ip = "";
            string uuid = "";
            foreach (var dcpdata in _collectedResponses[index].dcpPacket.GetDcpDataPackages())
            {
                if (dcpdata.ip() != "")
                {
                    ip = dcpdata.ip();
                }
                if (dcpdata.ToGuid() != Guid.Empty)
                {
                    uuid = dcpdata.ToGuid().ToString();
                }
            }
            Console.WriteLine("slot: 0");
            Console.WriteLine("sub slot: 1");
            Console.WriteLine("IM_Tag_function: ");
            var content = Console.ReadLine();

            BuilderClass.seqnr = 0;
            BuilderClass.rpc_seqnr = 0;

            Send(_collectedResponses[index].mac, ip, ImplicitReadReq(uuid, BuilderClass.index_im0filter, "00 00", "00 00", BuilderClass.rpc_activity_uuid));
            Thread.Sleep(1);
            Send(_collectedResponses[index].mac, ip, ImplicitReadReq(uuid, BuilderClass.index_im1, "00 00", "00 01", BuilderClass.rpc_activity_uuid));
            Thread.Sleep(1);
            Send(_collectedResponses[index].mac, ip, ConnectRequest(uuid, _macSource1));
            Thread.Sleep(400);
            Send(_collectedResponses[index].mac, ip, WriteReq(uuid, content));
            Thread.Sleep(400);
            Send(_collectedResponses[index].mac, ip, ConnectionReleaseReq(uuid));
        }
      
        private static byte[] ImplicitReadReq(string objectuuid, string filter, string slot2, string subslot2, string rpc_activity_uuid)
        {
            // vaiireren von: io_device interface uuid;  und die variablen // "00 09", "00 01", "00 00", "00 01"
            var x = BuilderClass.BuildIODHeader(BuilderClass.iod_ar_null_uuid, BuilderClass.iod_ar_null_uuid, filter, "00 09", slot2, subslot2);
            var y = BuilderClass.BuildRpcNrdDataReq(objectuuid, BuilderClass.rpc_DeviceInterface, rpc_activity_uuid, x, "00 05");
            return y.HexToByteArray();
        }

        private static byte[] ConnectRequest(string objectuuid, string initiator_mac)
        {
            initiator_mac = initiator_mac.HexShort();
            //var activity_UUID = BuilderClass.rpc_activity_uuid;
            var x = BuilderClass.BuildArBlockReq(BuilderClass.iod_ar_custom_uuid, initiator_mac, BuilderClass.iod_ar_initiatorobject_uuid);
            var y = BuilderClass.BuildRpcNrdDataReq(objectuuid, BuilderClass.rpc_ControllerInterface, BuilderClass.rpc_activity_uuid, x, "00 00");
            return y.HexToByteArray();
        }

        private static byte[] ReadReq(string objectuuid, string index, string slot2, string subslot2)
        {
            // TODO
            // vaiireren von: io_device interface uuid;  und die variablen
            var x = BuilderClass.BuildIODHeader(BuilderClass.iod_ar_custom_uuid, BuilderClass.iod_targetar_custom_uuid, index, "00 09", slot2, subslot2);
            var y = BuilderClass.BuildRpcNrdDataReq(objectuuid, BuilderClass.rpc_DeviceInterface, BuilderClass.rpc_activity_uuid, x, "00 02");
            return y.HexToByteArray();
        }

        private static byte[] WriteReq(string objectuuid, string content)
        {

            var im0 = new Im1Block()
            {
                header = "0021 xxxx 01 00".HexShort(),
                body = content.PadRight(32, ' ').StringToHex() + "".PadLeft(22, ' ').StringToHex()
            };
            var x2 = im0.Build();
            var x = BuilderClass.BuildIODHeaderContent(BuilderClass.iod_ar_custom_uuid, BuilderClass.iod_ar_null_uuid, BuilderClass.index_im1, "00 08", "00 00", "00 01", x2 );
           
            var y = BuilderClass.BuildRpcNrdDataReq(objectuuid, BuilderClass.rpc_DeviceInterface, BuilderClass.rpc_activity_uuidim1w, x,"00 03");
            return y.HexToByteArray();
        }

        private static byte[] ConnectionReleaseReq(string objectuuid)
        {
            var x = BuilderClass.BuildIodReleaseBlockReq(BuilderClass.iod_ar_custom_uuid);
            var y = BuilderClass.BuildRpcNrdDataReq(objectuuid, BuilderClass.rpc_ControllerInterface, BuilderClass.rpc_activity_uuid, x, "00 01");
            return y.HexToByteArray();
        }
        
        static void Send(string macDest, byte[] content)
        {
            {
                communicator.SendPacket(BuildEthernetPacket(macDest, content));
            }
        }

        static void Send(string macDest, string ipdest, byte[] content)
        {
            {
                communicator.SendPacket(BuildUdpPacket(macDest, ipdest, content));
            }
        }


        // RECIVE
        // Method for reciving packets on specified device
        static void Recive(int number, HandlePacket packetHandler)
        {
            // Open the device
            using (PacketCommunicator communicatorX =
                selectedDevice.Open(65536,                                  // portion of the packet to capture
                                                                            // 65536 guarantees that the whole packet will be captured on all the link layers
                                    PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                    1000))                                  // read timeout
            {
                Console.WriteLine("");
                Console.WriteLine("Listening: ");

                // start the capture
                // Callback function invoked by Pcap.Net for every incoming packet
                communicatorX.ReceivePackets(number, packetHandler);
            }
        }

        static void UDPDefaultHandler(Packet packet)
        {
            HighlightConsole(true, 2);
            try
            {
                if (packet?.Ethernet?.IpV4?.Destination.ToString() == _ipSource1)
                {
                    if (packet?.Ethernet?.IpV4?.Udp?.DestinationPort == 34964)
                    {
                        Console.WriteLine("");

                        var rcppacket = (RpcHeader)packet.Ethernet.IpV4.Udp.Payload.ToArray().ByteArrayToHex();
                        var x = rcppacket.getActivityUUID();

                        if (x.EndsWith(BuilderClass.myuuid_suffiximf))
                        {
                            Console.WriteLine("packet length: " + packet.Length);
                            Console.WriteLine("Status: " + rcppacket.getStatusText());
                            Console.WriteLine("I&M 0 FILTER data:");

                            var nrd = (NrdDataReqResp)rcppacket.body/*.Substring(4*2)*/;
                            var i = 0;
                            var count_pre = nrd.body.Length;
                            while (i < count_pre)
                            {
                                var iod = (IodHeaderRead)nrd.body.Substring(i);
                                i = i + iod.header.Length + iod.body.Length;

                                try
                                {
                                    var ii = 14 * 2;
                                    while (ii < iod.body.Length)
                                    {
                                        var subopt = iod.body.HexGetNextBytes(ref ii, 14);
                                        Console.WriteLine("slot: " + subopt.Substring(0, 2 * 2) + " and subslot: " + subopt.Substring(8*2, 2 * 2));
                                    }
                                }
                                catch { }

                            }
                        }
                        if (x.EndsWith(BuilderClass.myuuid_suffix3))
                        {
                            Console.WriteLine("packet length: " + packet.Length);
                            Console.WriteLine("Status: " + rcppacket.getStatusText());
                            Console.WriteLine("I&M 0 DATA:");


                            var nrd = (NrdDataReqResp)rcppacket.body/*.Substring(4*2)*/;
                            var i = 0;
                            var count_pre = nrd.body.Length;
                            while (i < count_pre)
                            {
                                var iod = (IodHeaderReadResp)nrd.body.Substring(i);
                                i = i + iod.header.Length + iod.body.Length;

                                try
                                {
                                    Console.WriteLine("vendor: " + iod.body.Substring(6*2 , 2 * 2));
                                    Console.WriteLine("order: " + iod.body.Substring(8 * 2, 20 * 2).HexToString());
                                    Console.WriteLine("serialnr: " + iod.body.Substring(28 * 2, 16 * 2).HexToString());
                                    Console.WriteLine("rest: " + iod.body.Substring(44 * 2));
                                }
                                catch{ }
                            }
                        }

                        if (x.EndsWith(BuilderClass.myuuid_suffixim1w))
                        {
                            Console.WriteLine("packet length: " + packet.Length);
                            Console.WriteLine("Status: " + rcppacket.getStatusText());
                            Console.WriteLine("I&M 1 response");
                        }

                        if (x.EndsWith(BuilderClass.myuuid_suffixim1r))
                        {
                            Console.WriteLine("packet length: " + packet.Length);
                            Console.WriteLine("Status: " + rcppacket.getStatusText());
                            Console.WriteLine("I&M 1 DATA:");


                            var nrd = (NrdDataReqResp)rcppacket.body/*.Substring(4*2)*/;
                            var i = 0;
                            var count_pre = nrd.body.Length;
                            while (i < count_pre)
                            {
                                var iod = (IodHeaderReadResp)nrd.body.Substring(i);
                                i = i + iod.header.Length + iod.body.Length;

                                try
                                {
                                    Console.WriteLine("function: " + iod.body.Substring(6*2, 32*2).HexToString());
                                    Console.WriteLine("tag: " + iod.body.Substring(38*2, 22 * 2).HexToString());
                                }
                                catch { }
                            }
                        }
                    }

                }
            }
            catch (Exception ex)
            { LowlightConsole(ex.Message); }
            HighlightConsole(false);

        }

        static void DefaultPacketHandler(Packet packet)
        {
            if (packet.Ethernet.Destination.Equals(new MacAddress(_macSource1)))
            {
                string macsource = packet.Ethernet.Source.ToString();
                string content = packet.Buffer.ByteArrayToHex();
                HighlightConsole(true, 2);
                try
                {
                    var dcppacket = new DcpPacket(content);
                    if (dcppacket._xid.Equals(TRANSACT_ID))
                    {
                        Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " matching xid to us, length:" + packet.Length);
                        if (dcppacket._serviceType.EndsWith("01"))
                            HighlightConsole("dcp - success");
                        else
                            Console.WriteLine(dcppacket._serviceType);
                        // Matching ID and matching dest.
                        Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " matching xid to us, length:" + packet.Length);
                        foreach (var dcpdata in dcppacket.GetDcpDataPackages())
                        {
                            if (dcpdata._statusHex == "00")
                                HighlightConsole("block - ok");
                            else
                                Console.WriteLine(dcpdata._statusHex);
                        }

                    }
                }
                catch (Exception ex)
                { LowlightConsole(ex.Message); }
                Console.WriteLine("");
                HighlightConsole(false);


            }
        }

        static void IdentificationResponseHandler(Packet packet)
        {
            if (packet.Ethernet.Destination.Equals(new MacAddress(_macSource1)))
            {
                string macsource = packet.Ethernet.Source.ToString();
                string content = packet.Buffer.ByteArrayToHex();
                try
                {
                    var dcppacket = new DcpPacket(content);
                    if (dcppacket._xid.Equals(TRANSACT_ID))
                    {
                        // Matching ID and matching dest.

                        var response = new Response()
                        {
                            mac = macsource,
                            dcpPacket = dcppacket
                        };

                        int index = _collectedResponses.FindIndex(x => x.mac.Equals(macsource));
                        if (index >= 0)
                        {
                            _collectedResponses[index] = response;
                        }
                        else
                        {
                            _collectedResponses.Add(response);
                        }
                    }
                }
                catch
                { }
                PrintAllResponses();
            }
        }

        private static void HighlightConsole(bool onoff, int color = 0)
        {
            if (onoff)
            {
                if (color == 0)
                {
                    Console.BackgroundColor = ConsoleColor.Yellow;
                    Console.ForegroundColor = ConsoleColor.Black;
                }
                else if (color == 2)
                {
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.Cyan;
                }
                else
                {
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                }
            }
            else
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.White;
            }
        }

        private static void HighlightConsole(string input)
        {
            HighlightConsole(true);
            Console.WriteLine(input);
            HighlightConsole(false);
        }

        private static void LowlightConsole(string input)
        {
            HighlightConsole(true, 1);
            Console.WriteLine(input);
            HighlightConsole(false);
        }

        static void PrintAllResponses()
        {
            Console.WriteLine("");
            Console.WriteLine("");
            Console.WriteLine("");
            Console.WriteLine("Awnsers: ");
            for (int i = 0; i < _collectedResponses.Count; i++)
            {
                Console.WriteLine("");
                Console.WriteLine("");
                HighlightConsole(true);
                Console.WriteLine(i + ":     MAC : " + _collectedResponses[i].mac);
                HighlightConsole(false);
                //Console.WriteLine(_collectedResponses[i].dcpPacket.ToString());
                foreach (var dcpdata in _collectedResponses[i].dcpPacket.GetDcpDataPackages())
                {
                    if (dcpdata.ToGuid() != Guid.Empty)
                    {
                        Console.WriteLine("        guid    " + dcpdata.ToGuid());
                    }
                    else if (dcpdata.ip() != "")
                    {
                        Console.WriteLine("        ip      " + dcpdata.ip());
                        Console.WriteLine("        subnet  " + dcpdata.subnet());
                        Console.WriteLine("        gateway " + dcpdata.gateway());
                    }
                    else if (dcpdata.geraeterolle() != "")
                    {
                        Console.WriteLine("                " + dcpdata.geraeterolle());
                    }
                    else
                        Console.WriteLine(dcpdata.ToString());
                }
            }
            Console.WriteLine("");

        }

        /// <summary>
        /// This function build an Ethernet with payload packet.
        /// </summary>
        static Packet BuildEthernetPacket(string macdest, byte[] content)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress(_macSource1),
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


        private static Packet BuildUdpPacket(string macdest, string ipdest, byte[] content)
        {
            EthernetLayer ethernetLayer =
                new EthernetLayer
                {
                    Source = new MacAddress(_macSource1),
                    Destination = new MacAddress(macdest),
                    EtherType = EthernetType.None, // Will be filled automatically.
                };

            IpV4Layer ipV4Layer =
                new IpV4Layer
                {
                    Source = new IpV4Address(_ipSource1),
                    CurrentDestination = new IpV4Address(ipdest),
                    Fragmentation = IpV4Fragmentation.None,
                    HeaderChecksum = null, // Will be filled automatically.
                    Identification = 123,
                    Options = IpV4Options.None,
                    Protocol = null, // Will be filled automatically.
                    Ttl = 100,
                    TypeOfService = 0,
                };

            UdpLayer udpLayer =
                new UdpLayer
                {
                    SourcePort = 34964,
                    DestinationPort = 34964,
                    Checksum = null, // Will be filled automatically.
                    CalculateChecksumValue = true,
                };

            PayloadLayer payloadLayer =
                new PayloadLayer
                {
                    Data = new Datagram(content),
                };

            PacketBuilder builder = new PacketBuilder(ethernetLayer, ipV4Layer, udpLayer, payloadLayer);

            return builder.Build(DateTime.Now);
        }

    }

    // helper class
    public static class h
    {
        /*
         * UMWANDLUNGEN
         * 
         * parsing
         * byte[] -> hex #
         * hex -> string #
         * hex -> int #
         * 
         * combining
         * string -> hex #
         * int -> hex #
         * hex -> byte[] #
         */


        // String HEX
        public static byte[] HexToByteArray(this string hex)
        {
            if (hex.Length % 2 == 1)
                hex = 0 + hex;
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static string HexToString(this string hex)
        {
            return Encoding.UTF8.GetString(HexToByteArray(hex));
        }

        public static int HexToInt(this string hex)
        {
            var i = int.Parse(hex, System.Globalization.NumberStyles.HexNumber);
            return i;
        }

        public static int HexGetNrOfBytes(this string hex)
        {
            return hex.Length / 2;
        }

        public static string HexGetNextBytes(this string hex, ref int counter, int numberOfBytes)
        {
            numberOfBytes *= 2;
            var x = hex.Substring(counter, numberOfBytes);
            counter = counter + numberOfBytes;
            return x;
        }

        // String utf8

        public static string StringToHex(this string utf8)
        {
            return ByteArrayToHex(Encoding.UTF8.GetBytes(utf8));
        }

        public static string Replace(this string text, int begin, string replacedBy)
        {
            return text.Remove(begin, replacedBy.Length).Insert(begin, replacedBy);
        }

        // Byte Array
        public static string ByteArrayToHex(this byte[] bytearray)
        {
            StringBuilder hex = new StringBuilder(bytearray.Length * 2);
            foreach (byte b in bytearray)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public static string ByteArrayToStringInts(this byte[] bytearray)
        {
            StringBuilder hex = new StringBuilder(bytearray.Length * 2);
            foreach (byte b in bytearray)
                hex.AppendFormat("{0}.", b);
            return hex.ToString();
        }

        public static string ByteArrayToString(this byte[] bytearray)
        {
            return Encoding.UTF8.GetString(bytearray);
        }

        public static byte[] Append(this byte[] original, byte[] append)
        {
            byte[] ret = new byte[original.Length + append.Length];
            Array.Copy(original, 0, ret, 0, original.Length);
            Array.Copy(append, 0, ret, original.Length, append.Length);
            return ret;
        }

        public static string HexShort(this string hex)
        {
            return hex.Replace(" ", "").Replace("-", "").Replace("(", "").Replace(")", "").Replace("x", "0").Replace(":", "");
        }


        // int
        public static string IntToHex(this int value, int padding)
        {
            var hex = value.ToString("X");
            var pad = hex.PadLeft(padding, '0');
            return pad.Substring(0, padding);
        }
    }
}
