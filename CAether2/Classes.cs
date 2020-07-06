using System.Collections.Generic;

namespace CaEthernet
{
    public class DcpData
    {
        public string _optionHex;
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
            var lengthInt = lengthHex.HexToInt();
            _statusHex = packageRawHex.Substring(6, 2);
            _contentHex = packageRawHex.Substring(8, lengthInt * 2);
            rest = packageRawHex.Substring(8 + lengthInt * 2);

            if (_optionHex == "0000" && lengthHex == "0000")
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
            //_dataLength = rawHex.Substring(beginn + 20, 4);
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

        public byte[] Build()
        {
            //fefe0500123456780001 0004ffff
            //fefe0400123456780001 0002ffff

            //fefd040012345678 0000 000c 0202 0006 0000746573743434
            // 02" + "02" + "0007" + "0000" + "316531743100";
            var s = _frameId + _serviceId + _serviceType + _xid + _rdf + _data.HexGetNrOfBytes().IntToHex(4) + _data;
            var b = s.HexToByteArray();
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
}