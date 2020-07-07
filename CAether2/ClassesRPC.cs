﻿using PcapDotNet.Core;
using PcapDotNet.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Text;
using System.Threading.Tasks;

namespace CaEthernet
{
    //public class RpcPacket
    //{
    //    public byte[] header;
    //    public byte[] body;

    //    public const int lengthsize = 2;
    //    public const int lengthindex = 74;
    //    public const int headersize = 80;

    //    public byte[] Build()
    //    {
    //        var all = header.Append(body);
    //        body.Length.IntToByteArray(lengthsize).CopyTo(all, lengthindex);
    //        return all;
    //    }

    //    public static int GetBodyLength(byte[] input)
    //    {
    //        int bodylength;
    //        if (lengthsize == 2)
    //            bodylength = BitConverter.ToUInt16(input, lengthindex);
    //        if (lengthsize == 4)
    //            bodylength = BitConverter.ToInt32(input, lengthindex);
    //        return bodylength;
    //    }

    //    public static explicit operator RpcPacket (byte[] input)
    //    {
    //        var bodylength = RpcPacket.GetBodyLength(input);
    //        RpcPacket output = new RpcPacket()
    //        {
    //            header = new byte[headersize],
    //            body = new byte[bodylength]
    //        };
    //        input.BlockCopy(0, output.header, 0, headersize);
    //        input.BlockCopy(headersize, output.body, 0, bodylength);
    //        return output;
    //    }
    //}


    public class RpcHeader
    {
        public string header;
        public string body;

        public const int lengthsize = 2*2;
        public const int lengthindex = 74*2;
        public const int headersize = 80*2;

        public string Build()
        {
            var all = header + body;
            all = all.Remove(lengthindex, lengthsize).Insert(lengthindex, body.HexGetNrOfBytes().IntToHex(lengthsize));
            return all;
        }

        public static int GetBodyLength(string header)
        {
            return header.Substring(lengthindex, lengthsize).HexToInt();
        }

        public static explicit operator RpcHeader(string hex)
        {
            var bodylength = RpcHeader.GetBodyLength(hex);
            return new RpcHeader()
            {
                header = hex.Substring(0,headersize),
                body = hex.Substring(headersize, bodylength),
            };
        }
    }

    public class NrdDataReqResp
    {
        public string header;
        public string body;

        public const int lengthsize = 4*2;
        public const int lengthindex = 4*2;
        public const int headersize = 20*2;

        public string Build()
        {
            var all = header + body;
            all = all.Remove(lengthindex, lengthsize).Insert(lengthindex, body.HexGetNrOfBytes().IntToHex(lengthsize));
            all = all.Remove(16 * 2, lengthsize).Insert(16*2, body.HexGetNrOfBytes().IntToHex(lengthsize));
            return all;
        }

        public static int GetBodyLength(string header)
        {
            return header.Substring(lengthindex, lengthsize).HexToInt();
        }

        public static explicit operator NrdDataReqResp(string hex)
        {
            var bodylength = NrdDataReqResp.GetBodyLength(hex);
            return new NrdDataReqResp()
            {
                header = hex.Substring(0, headersize),
                body = hex.Substring(headersize, bodylength),
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
            all = all.Remove(headersizeindex, headersizeindexsize).Insert(headersizeindex, ((headersize - headersizeindex - headersizeindexsize)/2).IntToHex(headersizeindexsize));
            return all;
        }
    }

    public class IodHeader : IodStandardBase
    {
        public string body;

        public const int lengthsize = 4 * 2;
        public const int lengthindex = 36 * 2;
        public const int headersize_c = 64 * 2;

        public override int headersize => headersize_c;

        public new string Build()
        {
            var all = base.Build();

            all += body;
            all = all.Remove(lengthindex, lengthsize).Insert(lengthindex, body.HexGetNrOfBytes().IntToHex(lengthsize));
            return all;
        }

        public static int GetBodyLength(string header)
        {
            return header.Substring(lengthindex, lengthsize).HexToInt();
        }

        public static explicit operator IodHeader(string hex)
        {
            var bodylength = IodHeader.GetBodyLength(hex);
            return new IodHeader()
            {
                header = hex.Substring(0, headersize_c),
                body = hex.Substring(headersize_c, bodylength),
            };
        }
    }

    public class IodReleaseBlock : IodStandardBase
    {
        public const int headersize_c = 32;

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

        //static string iodeviceuuid = "dea00001-6c97-11d1-8271-00a02442df7d";
        public static string myactivityuuid = "dea00001-6c97-11d1-8271-123456789012";
        public static string mynulluuid = "00000000-0000-0000-0000-000000000000";

        public static string UUID_IO_DeviceInterface = "dea00001-6c97-11d1-8271-00a02442df7d";
        public static string UUID_IO_ControllerInterface = "dea00002-6c97-11d1-8271-00a02442df7d";
        public static string UUID_IO_SupervisorInterface = "dea00003-6c97-11d1-8271-00a02442df7d";
        public static string UUID_IO_ParameterServerInterface = "dea00004-6c97-11d1-8271-00a02442df7d";


        public static string ReadRequest(string objectid, string identid, string activityid, string NrdDataReqRespBody)
        {
            var pack = new RpcHeader()
            {
                header =(
                $"04 00 20 00 - 00 00 00 - 00 " +
                $"{objectid} " +
                $"{identid} " +
                $"{activityid} " +
                $"(00 00 00 00)" +
                $"(00 00 00 01) " +
                $"(00 00 00 01)" +
                $"(00 05) " +
                $"ffff ffff" +
                $"(xx xx) " +
                $"(00 00) 00 01"
                ).HexShort(),
                body = new NrdDataReqResp()
                {
                    // auch möglich: (00 00 02 51)
                    header =(
                    "(00 00 00 03)" +
                    "(xx xx xx xx) " +
                    "(00 00 00 03) " +
                    "(00 00 00 00) " +
                    "(xx xx xx xx)"
                    ).HexShort(),
                    body = NrdDataReqRespBody
                }.Build()
            };
            return pack.Build();
        }

        public static string BuildIODHeader(string arid, string targetarid, string index)
        {
            var x = new IodHeader()
            {
                header = (
                        $"(00 09) (xx xx) 01 00" +
                        $"(00 00)" +
                        $"{arid}" +
                        $"(00 00 00 00) (00 00) (00 00) (00 00) " +
                        $"{index} " +
                        $"(xx xx xx xx)" +
                        $"{targetarid} (00 00 00 00 - 00 00 00 00)"
                        ).HexShort(),
                body = "",
            }.Build();
            return x;
        }

    }


}
