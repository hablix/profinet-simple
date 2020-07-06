using PcapDotNet.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CaEthernet
{
    public class DcpData
    {
        public string _optionHex;
        //public string lengthHex;
        public string _statusHex;
        public string _contentHex;

        public static List<DcpData> ParseDcpDataPackages(string packageRawHex)
        {
            List<DcpData> list = new List<DcpData>();
            while (packageRawHex.Length > 0)
            {
                try
                {
                    string tmp;
                    list.Add(new DcpData(packageRawHex, out tmp));
                    packageRawHex = tmp;
                }
                catch { packageRawHex = string.Empty; }
            }
            return list;
        }

        public DcpData(string packageRawHex, out string rest)
        {
            _optionHex = packageRawHex.Substring(0, 4);
            var lengthHex = packageRawHex.Substring(4, 4);
            var lengthInt = lengthHex.HexToInt();// (Program.HexToByteArray(lengthHex)[0] << 8) | Program.HexToByteArray(lengthHex)[1];
            _statusHex = packageRawHex.Substring(6, 2);
            _contentHex = packageRawHex.Substring(8, lengthInt * 2);
            rest = packageRawHex.Substring(8 + lengthInt * 2);

            if(_optionHex == "0000" && lengthHex == "0000")
            {
                rest = string.Empty;
            }
        }

        public DcpData(string optionHex, string contentHex, string statusHex = "0000")
        {
            _optionHex = optionHex;
            _statusHex = statusHex;
            _contentHex = contentHex;
        }

        public string Build()
        {
            var postHex = _statusHex + _contentHex;
            //var lengthHex = postHex.HexGetHexLength(4); //Program.ByteArrayToHex(new byte[] { ((byte)(postHex.Length / 2))}).PadLeft(4, '0');

            if (_contentHex.Length % 2 == 1)
                _contentHex += "0";
            var s = _optionHex + postHex.HexGetNrOfBytes().IntToHex(4) + postHex;
            return s;
        }

        public override string ToString()
        {
            return _optionHex + " content: " + _contentHex.HexToString();
        }
    }

    public class DcpPacket
    {
        public string _frameId;
        public string _serviceId;
        public string _serviceType;
        public string _xid;
        public string _rdf;
        string _dataLength;
        public string _data;

        public List<DcpData> GetDcpDataPackages()
        {
            return DcpData.ParseDcpDataPackages(_data);
        }

        public DcpPacket()
        {
        }

        public DcpPacket(string rawHex)
        {
            var beginn = 28; // rawHex.IndexOf("feff", 24);
            _frameId = rawHex.Substring(beginn, 4);
            _serviceId = rawHex.Substring(beginn + 4, 2);
            _serviceType = rawHex.Substring(beginn + 6, 2);
            _xid = rawHex.Substring(beginn + 8, 8);
            _rdf = rawHex.Substring(beginn + 16, 4);
            _dataLength = rawHex.Substring(beginn + 20, 4);
            _data = rawHex.Substring(beginn + 24);
        }

        public void MakeIdentificationRequest(string xidHex = "12345678")
        {
            _frameId = "fefe";
            _serviceId = "05";
            _serviceType = "00";
            _xid = xidHex;
            _rdf = "0001";
            _data = "ffff0000";
        }

        public void MakeSetRequest(string data, string xidHex = "12345678")
        {
            _frameId = "fefd";
            _serviceId = "04";
            _serviceType = "00";
            _xid = xidHex;
            _rdf = "0000";
            _data = data;
        }

        public void MakeGetRequest(string data, string xidHex = "12345678")
        {
            _frameId = "fefd";
            _serviceId = "03";
            _serviceType = "00";
            _xid = xidHex;
            _rdf = "0000";
            _data = data;
        }

        static void BuildAndSend(string macDest, string frameId, string serviceID, string serviceType, string Xid, string responseDelayFactor, string dcpDataheader)
        {
            //fefe05001234567800010004ffff
            //fefe05001234567800010004ffff
            //fefe 05 00 12345678 0001 0004 ff ff
            //fefe04001234567800010002ffff
            string s = frameId + serviceID + serviceType + Xid + responseDelayFactor + Program.ByteArrayToHex(new byte[] { (byte)(dcpDataheader.Length / 2) }).PadLeft(4, '0') + dcpDataheader;


        }

        public byte[] Build()
        {
            //fefe0500123456780001 0004ffff
            //fefe0400123456780001 0002ffff

            //fefd040012345678 0000 000c 0202 0006 0000746573743434
            // 02" + "02" + "0007" + "0000" + "316531743100";
            var s = _frameId + _serviceId + _serviceType + _xid + _rdf + Program.ByteArrayToHex(new byte[] { (byte)(_data.Length / 2) }).PadLeft(4, '0') + _data;
            var b = Program.HexToByteArray(s);
            return b;
        }

        public override string ToString()
        {
            return _frameId + " " + _serviceId + " " + _serviceType + " " + _xid;
        }
    }

    public class Response
    {
        public string mac;
        public DcpPacket dcpPacket;
    }


    //        public class ProfinetDevice
    //    {

    //        /*
    //IP 0101 Mac-Adresse
    //IP 0102 IP-Parameter
    //DeviceProperties 0201 Herstellerspezifisch
    //DeviceProperties 0202 Stationsname
    //DeviceProperties 0203 DeviceID
    //DeviceProperties 0204 Geräterolle
    //DeviceProperties 0205 Optionen
    //DeviceProperties 0206 Aliasname des Device
    //         * 
    //         */

    //        public string mac;
    //        public string ipHex;
    //        public string herstellerspezifischHex;
    //        public string stationsnameHex;
    //        public string deviceidHex;
    //        public string geraterolleHex;
    //        public string optionenHex;
    //        public string aliasHex;

    //        public string stationsname { 
    //            get { return Encoding.ASCII.GetString(Program.HexToByteArray(stationsname));  }
    //            set { stationsnameHex = Program.ByteArrayToHex(Encoding.ASCII.GetBytes(value)); }
    //        }

    //        public void FromDcpDataPackages(string datapackagesHex)
    //        {
    //            while (datapackagesHex.Length > 0)
    //            {
    //                var pre = datapackagesHex.Substring(0, 4);
    //                var length = datapackagesHex.Substring(4, 4);
    //                var lengthInt = (Program.HexToByteArray(length)[0] << 8) | Program.HexToByteArray(length)[1];
    //                var content = datapackagesHex.Substring(8, lengthInt * 2);
    //                datapackagesHex = datapackagesHex.Substring(8 + lengthInt * 2);

    //                setValue(pre, content);
    //            }

    //        }

    //        private void Send(PacketDevice selectedDevice, string macDest, string contentInHex)
    //        {
    //            // Open the output device
    //            using (PacketCommunicator communicator = selectedDevice.Open(100, // name of the device
    //                                                                         PacketDeviceOpenAttributes.Promiscuous, // promiscuous mode
    //                                                                         1000)) // read timeout
    //            {
    //                var by = HexToByteArray(contentInHex);
    //                communicator.SendPacket(BuildEthernetPacket(_macSource1, macDest, by));
    //                communicator.SendPacket(BuildEthernetPacket(_macSource2, macDest, by));

    //            }
    //        }

    //            public void SendSetRequest() { }

    //        static void SetRequest(int macindex)
    //        {
    //            //74 65 73 74 31 32 33
    //            //var s = "02" + "02" + "0007" +"0000"+ "7878787878787800";
    //            //var s = "02" + "02" + "0007" + "0000" + "316531743100";
    //            var ascii = "madita-und-hannes-waren-hier";
    //            var encoded = "0000" + ByteArrayToHex(Encoding.ASCII.GetBytes(ascii));

    //            var length = ByteArrayToHex(new byte[] { (byte)(encoded.Length / 2) }).PadLeft(4, '0');

    //            if (encoded.Length % 2 == 1)
    //                encoded += "0";

    //            SetRequest(macindex, "0202" + length + encoded);
    //        }


    //        public string jk ()
    //        {
    //            var s = "";
    //            s += FormDataPackage("")

    //        }

    //        private string FormDataPackage(string pre, string contentHex)
    //        {
    //            contentHex = "0000" + contentHex;
    //            var length = Program.ByteArrayToHex(new byte[] { (byte)(contentHex.Length / 2) }).PadLeft(4, '0');

    //            if (contentHex.Length % 2 == 1)
    //                contentHex += "0";
    //            var s = pre + length + contentHex;
    //            return s;
    //        }


    //        private void setValue(string preHex, string contentHex)
    //        {
    //            switch (preHex)
    //            {
    //                //case "0101":
    //                //    macHex = contentHex;
    //                //    break;
    //                case "0102":
    //                    ipHex = contentHex;
    //                    break;
    //                case "0201":
    //                    herstellerspezifischHex = contentHex;
    //                    break;
    //                case "0202":
    //                    stationsnameHex = contentHex;
    //                    break;
    //                case "0203":
    //                    deviceidHex = contentHex;
    //                    break;
    //                case "0204":
    //                    geraterolleHex = contentHex;
    //                    break;
    //                case "0205":
    //                    optionenHex = contentHex;
    //                    break;
    //                case "0206":
    //                    aliasHex = contentHex;
    //                    break;
    //            }
    //        }


}
