using PcapDotNet.Core;
using PcapDotNet.Packets;
using System;
using System.Collections.Generic;
using System.Linq;
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

    public class IodHeader
    {
        public string header;
        public string body;

        public const int lengthsize = 4 * 2;
        public const int lengthindex = 36 * 2;
        public const int headersize = 64 * 2;

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

        public static explicit operator IodHeader(string hex)
        {
            var bodylength = IodHeader.GetBodyLength(hex);
            return new IodHeader()
            {
                header = hex.Substring(0, headersize),
                body = hex.Substring(headersize, bodylength),
            };
        }
    }


    public class BlockHeader
    {
        public string header;
        public string body;

        public const int lengthsize = 2 * 2;
        public const int lengthindex = 2 * 2;
        public const int headersize = 6 * 2;

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

        public static explicit operator BlockHeader(string hex)
        {
            var bodylength = BlockHeader.GetBodyLength(hex);
            return new BlockHeader()
            {
                header = hex.Substring(0, headersize),
                body = hex.Substring(headersize, bodylength),
            };
        }
    }




}
