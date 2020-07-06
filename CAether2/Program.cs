﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
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
        static string _ipSource1 = "141.76.83.220";
        //static string _macSource2 = "C4:E9:84:00:41:2D"; //2 //172.11.4.82 //nicht genuztz

        //static string macSiemens = "00:0E:8C:87:29:55";

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

            Console.WriteLine("\n\n Type " +
                "\n 'i' for identification request " +
                "\n 's' for set name to listed mac " +
                "\n 'z' for set name to custom mac " +
                "\n 'u' for set name to custom mac " +
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
                Console.WriteLine("type device to respond to: ");
                Console.WriteLine("type in mac adress in style 00:00:00:00:00:00" );
                try
                {
                    Sationsname(Console.ReadLine());
                }
                catch (Exception ex)
                { Console.WriteLine(ex.Message); }
            }

            if (val == "s")
            {
                try
                {
                    PrintAllResponses();
                    Console.WriteLine("type device to respond to: ");
                    int index = 0;
                    do
                        Console.WriteLine("type in mac adress index from 0 to " + (_collectedResponses.Count - 1));
                    while (!int.TryParse(Console.ReadLine(), out index) && index > 0 && index < (_collectedResponses.Count - 1));
                    Sationsname(_collectedResponses[index].mac);
                }
                catch (Exception ex)
                { Console.WriteLine(ex.Message); }
            }


            if (val == "u")
            {
                try
                {
                    
                }
                catch (Exception ex)
                { }
            }


            goto begin;
        }

        private static void Sationsname(string mac)
        {
            Console.WriteLine("neuer Stationsname: ");
            var value = Console.ReadLine();
            SendSetRequest(mac, "0202", Program.ByteArrayToHex(Encoding.ASCII.GetBytes(value)));
            Recive(10, DefaultPacketHandler);

        }

        private static void Get(string mac)
        {
            Console.WriteLine("value:");
            var value = Console.ReadLine();
            SendGetRequest(mac, value, "");
            Recive(10, DefaultPacketHandler);

        }

        private static void ListAllDevices()
        {
            SendIdentificationRequest();
            Recive(30, IdentificationResponseHandler);
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
            Send(mac, dcppacket.Build());
        }

        static void SendGetRequest(string mac, string option, string contentHex)
        {
            var dcpdata = new DcpData(option, contentHex);
            var dcppacket = new DcpPacket();
            dcppacket.MakeGetRequest(dcpdata.Build());
            Send(mac, dcppacket.Build());
        }

        static void Send(string macDest, byte[] content)
        {
            // Open the output device
            using (PacketCommunicator communicator = selectedDevice.Open(100, // name of the device
                                                                         PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                                                         1000)) // read timeout
            {
                communicator.SendPacket(BuildEthernetPacket( macDest, content));
            }
        }

        static void Send(string macDest, string ipdest, byte[] content)
        {
            // Open the output device
            using (PacketCommunicator communicator = selectedDevice.Open(100, // name of the device
                                                                         PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
                                                                         1000)) // read timeout
            {
                communicator.SendPacket(BuildUdpPacket(macDest, ipdest, content));
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
            if (packet.Ethernet.Destination.Equals(new MacAddress(_macSource1)))
            {
                string macsource = packet.Ethernet.Source.ToString();
                string content = ByteArrayToHex(packet.Buffer);

                try
                {
                    var dcppacket = new DcpPacket(content);
                    if (dcppacket._xid.Equals(TRANSACT_ID))
                    {
                        // Matching ID and matching dest.
                        Console.WriteLine(packet.Timestamp.ToString("yyyy-MM-dd hh:mm:ss.fff") + " matching xid to us, length:" + packet.Length);
                        Console.WriteLine(" Adress: " + macsource);
                        foreach (var dcpdata in dcppacket.GetDcpDataPackages())
                        {
                            Console.WriteLine(dcpdata.ToString());
                        }
                        Console.WriteLine("raw: " + Encoding.UTF8.GetString(packet.Buffer));
                        Console.WriteLine("");

                    }
                }
                catch (Exception ex)
                { Console.WriteLine(ex.Message); }
            }
        }

        static void IdentificationResponseHandler(Packet packet)
       {
            if (packet.Ethernet.Destination.Equals(new MacAddress(_macSource1)))
            {
                string macsource = packet.Ethernet.Source.ToString();
                string content = ByteArrayToHex(packet.Buffer);
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
                    if(dcpdata._optionHex == "0102")
                    {
                        // parse ip adress:
                        var counter = 2*2;
                        Console.WriteLine("ip      " + dcpdata._contentHex.HexGetNextBytes(ref counter, 4).HexToByteArray().ByteArrayToStringInts());
                        Console.WriteLine("subnet  " + dcpdata._contentHex.HexGetNextBytes(ref counter, 4).HexToByteArray().ByteArrayToStringInts());
                        Console.WriteLine("gateway " + dcpdata._contentHex.HexGetNextBytes(ref counter, 4).HexToByteArray().ByteArrayToStringInts());

                    }
                }
            }
        }

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
            return Encoding.UTF8.GetString(Program.HexToByteArray(hex));
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
            counter += numberOfBytes;
            return x;
        }

        // String utf8

        public static string StringToHex(this string utf8)
        {
            return ByteArrayToHex(Encoding.UTF8.GetBytes(utf8));
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

        // int
        public static string IntToHex(this int value, int padding)
        {
            var hex = value.ToString("X");
            var pad = hex.PadLeft(padding, '0');
            return pad.Substring(0, padding);
        }


        //public static string HexGetHexLength(this string hex, int padding)
        //{
        //    return Program.ByteArrayToHex(new byte[] { (byte)(hex.Length / 2) }).PadLeft(padding, '0');
        //}
    }
}
