using PcapDotNet.Core;
using PcapDotNet.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;

namespace CaEthernet
{
    public class RpcHeader
    {
        public string header;
        public string body;

        public const int lengthsize = 2 * 2;
        public const int lengthindex = 74 * 2;
        public const int headersize = 80 * 2;

        public string Build()
        {
            var all = header + body;
            all = all.Remove(lengthindex, lengthsize).Insert(lengthindex, body.HexGetNrOfBytes().IntToHex(lengthsize));
            return all;
        }

        public static int GetBodyLength(string header, int max = -1)
        {
            var nr = header.Substring(lengthindex, lengthsize).HexToInt();
            if (max > 0 && nr > max)
            {
                return header.Substring(lengthindex, lengthsize - 2).HexToInt();
            }
            return nr;
        }

        public static explicit operator RpcHeader(string hex)
        {
            //var bodylength = RpcHeader.GetBodyLength(hex, hex.Length);
            return new RpcHeader()
            {
                header = hex.Substring(0, headersize),
                body = hex.Substring(headersize/*, bodylength*/),
            };
        }

        public string getPacketType()
        {
            return header.Substring(1 * 2, 1 * 2);
        }

        public string getOperationNumber()
        {
            return header.Substring(68 * 2, 2 * 2);
        }

        public string getStatusText()
        {
            var s = "";
            switch (getPacketType().HexToInt())
            {
                case 0:
                    s += "Request";
                    break;
                case 1:
                    s += "Ping";
                    break;
                case 2:
                    s += "Response";
                    break;
                case 3:
                    s += "Fault";
                    break;
                case 4:
                    s += "Working";
                    break;
                case 5:
                    s += "No call";
                    break;
                case 6:
                    s += "Reject";
                    break;
                case 7:
                    s += "Acknowledge";
                    break;
                case 8:
                    s += "Connectionless cancel";
                    break;
            }
            s += " - ";
            switch (getOperationNumber().HexToInt())
            {
                case 0:
                    s += "Connect";
                    break;
                case 1:
                    s += "Release";
                    break;
                case 2:
                    s += "Read";
                    break;
                case 3:
                    s += "Write";
                    break;
                case 4:
                    s += "Control";
                    break;
                case 5:
                    s += "Implicit read";
                    break;
                default:
                    s += "reserved";
                    break;
            }
            return s;
        }


        public string getActivityUUID()
        {
            return header.Substring(40 * 2, 16 * 2);
        }
    }

    public class NrdDataReqResp
    {
        public string header;
        public string body;

        public const int lengthsize = 4 * 2;
        public const int lengthindex = 4 * 2;
        public const int headersize = 20 * 2;

        public string Build()
        {
            var all = header + body;
            all = all.Remove(lengthindex, lengthsize).Insert(lengthindex, body.HexGetNrOfBytes().IntToHex(lengthsize));
            all = all.Remove(16 * 2, lengthsize).Insert(16 * 2, body.HexGetNrOfBytes().IntToHex(lengthsize));
            return all;
        }

        public static explicit operator NrdDataReqResp(string hex)
        {
            return new NrdDataReqResp()
            {
                header = hex.Substring(0, headersize),
                body = hex.Substring(headersize),
            };
        }
    }
    public abstract class IodStandardBase
    {
        public string header;

        public abstract int headersize { get; }
        public const int headersizeindex = 2 * 2;
        public const int headersizeindexsize = 2 * 2;

        public string Build()
        {
            var all = header;
            all = all.Remove(headersizeindex, headersizeindexsize).Insert(headersizeindex, ((headersize - headersizeindex - headersizeindexsize) / 2).IntToHex(headersizeindexsize));
            return all;
        }
    }

    public class IodHeaderRead : IodStandardBase
    {
        public string body;

        public const int lengthsize = 4 * 2;
        public const int lengthindex = 36 * 2;
        public const int headersize_c = 64 * 2;

        public const int expectedLength = 4096;

        public override int headersize => headersize_c;

        public new string Build()
        {
            var all = base.Build();

            all += body;
            all = all.Replace(lengthindex, expectedLength.IntToHex(lengthsize));
            return all;
        }

        public static int GetBodyLength(string header)
        {
            return header.Substring(lengthindex, lengthsize).HexToInt();
        }

        public static explicit operator IodHeaderRead(string hex)
        {
            var bodylength = IodHeaderRead.GetBodyLength(hex);
            return new IodHeaderRead()
            {
                header = hex.Substring(0, headersize_c),
                body = hex.Substring(headersize_c, bodylength),
            };
        }
    }

    public class ArBlockRequest : IodStandardBase
    {
        public const int headersize_c = 58 * 2 + 4 * 2; // + cminitiatorStationname octetstrin 1-240 byte

        public override int headersize => headersize_c;

        public static explicit operator ArBlockRequest(string hex)
        {
            return new ArBlockRequest() { header = hex.Substring(0, headersize_c) };
        }
    }

    public class IodReleaseBlock : IodStandardBase
    {
        public const int headersize_c = 32 * 2;

        public override int headersize => headersize_c;

        public static explicit operator IodReleaseBlock(string hex)
        {
            return new IodReleaseBlock() { header = hex.Substring(0, headersize_c) };
        }
    }


    public static class BuilderClass
    {
        public const string index_im0filter = "f840";
        public const string index_im0 = "aff0";
        public const string index_im1 = "aff1";
        public const string index_im2 = "aff2";
        public const string index_im3 = "aff3";
        public const string index_im4 = "aff4";

        public static Random r = new Random();

        //static string iodeviceuuid = "dea00001-6c97-11d1-8271-00a02442df7d";
        //public static string myactivityuuid = "dea00001-6c97-11d1-8271-123456789012";


        //public static string mynulluuid = "00000000-0000-0000-0000-000000000000";

        //public static string myarid = "dea00001-6c97-11d1-8271-123456789012";
        //public static string myinitiatorid = "dea00000-6c97-11d1-8271-123456789012";

        //public static string UUID_IO_DeviceInterface = "dea00001-6c97-11d1-8271-00a02442df7d";
        //public static string UUID_IO_ControllerInterface = "dea00002-6c97-11d1-8271-00a02442df7d";
        //public static string UUID_IO_SupervisorInterface = "dea00003-6c97-11d1-8271-00a02442df7d";
        //public static string UUID_IO_ParameterServerInterface = "dea00004-6c97-11d1-8271-00a02442df7d";

        public static string iod_ar_null_uuid = "00000000-0000-0000-0000-000000000000";
        public static string iod_ar_custom_uuid = "10000000-0000-0000-2000-123456789012";
        public static string iod_targetar_custom_uuid = "10000000-0000-0000-2000-123456789012";
        public static string iod_ar_initiatorobject_uuid = "dea00000-6c97-11d1-8271-123456789012";


        public static string rpc_activity_uuid= "10000000-0000-0000-1000-123456789012";
        // random id führt zu nca_unk_if
        //public static string rpc_activity_uuid {  get{return "10000000-0000-0000-1000-12" + r.Next(1, 90000).IntToHex(8) + "12"; } }

        public static string rpc_DeviceInterface = "dea00001-6c97-11d1-8271-00a02442df7d";
        public static string rpc_ControllerInterface = "dea00002-6c97-11d1-8271-00a02442df7d";
        public static string rpc_SupervisorInterface = "dea00003-6c97-11d1-8271-00a02442df7d";
        public static string rpc_ParameterServerInterface = "dea00004-6c97-11d1-8271-00a02442df7d";

        public static string myuuid_suffix = "123456789012";

        // fkt
        public static string ar_sessionkey = "4444";

        // aufaddieren: seq nicht ok!!
        public static int seqnr = 1;
        // rpc aufaddieren ist ok
        public static int rpc_seqnr = 0;





        public static string BuildRpcNrdDataReq(string objectid, string interfaceid, string activityid, string NrdDataReqRespBody, string operationr2)
        {
            var pack = new RpcHeader()
            {
                header = (
                $"04" + // version
                $"00 " + // 0 = request; 2 = response ; 7 = ack
                $"20 00 " + // flags
                $"00 00 00" + // data rep //10 00 00 fkt nicht!
                $"00 " + // serial high
                $"{objectid} " +
                $"{interfaceid} " +
                $"{activityid} " +
                $"(00 00 00 00)" + // server boot time
                $"(00 00 00 01) " + // interface version
                $"{rpc_seqnr.IntToHex(4 * 2)} " + // sequence nr
                $"{operationr2}" + // operation nr // 0 = connect; 2 = read; 5 = implicit read => arid = 0
                $"ffff" + // interface hint
                $"ffff" + // hint
                $"(xx xx) " + // length
                $"(00 00)" + // fragment nr
                $" 00 00" // auth // serial low
                ).HexShort(),
                body = new NrdDataReqResp()
                {
                    // auch möglich: (00 00 02 51)
                    header = (
                    "(00 00 02 51)" + // args max status
                    "(xx xx xx xx) " + // length 
                    "(00 00 02 51) " + // args maximum
                    "(00 00 00 00) " + // offset
                    "(xx xx xx xx)" // length
                    ).HexShort(),
                    body = NrdDataReqRespBody
                }.Build()
            };
            rpc_seqnr += 1;
            return pack.Build();
        }

        public static string BuildIODHeader(string arid, string targetarid, string index, string blocktype = "0009", /*string seqnr = "00 01",*/ string slot2 = "00 00", string subslot2 = "00 01")
        {
            var x = new IodHeaderRead()
            {
                header = (
                        $"{blocktype}" + // block header
                        $"(xx xx) 01 00" + // block header length + version hig + low
                        $"{seqnr.IntToHex(2 * 2)}" + // seq nr
                        $"{arid}" + // aruuid frei bei implit read
                        $"(00 00 00 00)" + // api
                        $"{slot2}" + // slot
                        $"{subslot2} " + //sub slot
                        $"(00 00) " + // padding
                        $"{index} " + // index 
                        $"(xx xx xx xx)" // length
                                         //$"{targetarid} " + // target uuid
                                         //$"(00 00 00 00 - 00 00 00 00)" // padding
                        ).HexShort(),
                body = (
                        $"{targetarid} " + // target uuid
                        $"(00 00 00 00 - 00 00 00 00)" // padding
                        ).HexShort(),
            }.Build();
            //seqnr += 1;
            return x;
        }

        public static string BuildArBlockReq(string arid, string mac6, string initiatorojbectid, string blocktype = "0101", string artype = "0006")
        {
            var x = new ArBlockRequest()
            {
                header = (
                        $"{blocktype} (xx xx) 01 00" +
                        $"{artype}" +
                        $"{arid}" +
                        $"{ar_sessionkey}" + // session key
                        $"{mac6}" +
                        $"{initiatorojbectid}" +
                        $"00 00 01 31" + // 0191
                        // 3. bit von 0.. 31 muss 1 sein.  also auch 
                        // 0                    1                   2                   3
                        //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                        // |A|A|ARPROPERTIE|ARPROPERTIES RESERVED 2|A|ARP|A|ARPRO|A|A|ARPRO|
                        //  0 0 0           0                       0 0   1 1     1 ?     1
                        //  0       0       0       0       0       1       9       1       
                        // ARProperties_DeviceAccess = 1 / 1
                        // ARProperties_reserved_1 = 1 / 3
                        // ARProperties_ParametrizationServer=1 / 1
                        // ARProperties_SupervisorTakeoverAllowed = ? / 1
                        // ARProperties_State = 1 / 3
                        //
                        $"(02 58)" + // timeout factor
                        $"(88 92)" + // initiator udp rtport
                        $"(00 04)" + //names length
                        $"(31 32 33 34)" // name
                        ).HexShort(),
            }.Build();
            return x;
        }


        public static string BuildIodReleaseBlockReq(string arid, string blocktype = "0114" /*string sessionkey = "0000"*/)
        {
            var x = new IodReleaseBlock()
            {
                header = (
                        $"{blocktype} (xx xx) 01 00" +
                        $"00 00" + // padding
                        $"{arid}" +
                        $"{ar_sessionkey}" +
                        $"00 00" + // padding
                        $"(00 04)" + // control cmd
                        $"(00 00)" // control block prop
                        ).HexShort(),
            }.Build();
            return x;
        }

    }


}
