﻿using System;
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
            if (lengthInt % 2 == 1)
                lengthInt += 1;
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

        public Guid ToGuid()
        {
            if (_optionHex == "0203")
            {
                var preh = _contentHex.Substring(0, 2 * 2);
                var vendorId = _contentHex.Substring(2*2, 2 * 2);
                var deviceId = _contentHex.Substring(4 * 2, 2 * 2);
                var pre = "0001";
                return new Guid("dea00000-6c97-11d1-8271-" + pre + deviceId + vendorId);
            }
            else
                return Guid.Empty;
        }

        public string ip()
        {
            if (_optionHex == "0102")
            {
                return _contentHex.Substring(2*2, 8).HexToByteArray().ByteArrayToStringInts();
            }
            else
                return "";
        }
        public string subnet()
        {
            if (_optionHex == "0102")
            {
                return _contentHex.Substring(12, 8).HexToByteArray().ByteArrayToStringInts();
            }
            else
                return "";
        }
        public string gateway()
        {
            if (_optionHex == "0102")
            {
                return _contentHex.Substring(16,8).HexToByteArray().ByteArrayToStringInts();
            }
            else
                return "";
        }

        public string geraeterolle()
        {
            if (_optionHex == "0204")
            {
                try
                {
                    switch (_contentHex.Substring(5, 1).HexToInt())
                    {
                        case 0:
                            return "IO-Device";
                        case 1:
                            return "IO-Conroler";
                        case 2:
                            return "IO-Multidevice";
                        case 3:
                            return "IO-supervisor";
                    }
                }
                catch
                { }
            }
            return "";
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