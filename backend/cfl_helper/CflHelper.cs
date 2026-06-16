using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Web.Script.Serialization;

namespace ClawGuard.CflHelper
{
    [StructLayout(LayoutKind.Sequential)]
    public struct ECCPublicKeyBlob
    {
        public UInt32 BitLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] XCoordinate;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] YCoordinate;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ECCSignatureBlob
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] r;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] s;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct UkeyParamStruct
    {
        public IntPtr hDev;
        public IntPtr hApp;
        public IntPtr hContainer;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] pDevName;
        public UInt32 ulDevNameLen;
        public UInt32 ulRetryCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 100)]
        public byte[] pwd;
        public IntPtr hShareKey;
        public IntPtr hAgreement;
        public IntPtr hEncKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct VersionStruct
    {
        public byte major;
        public byte minor;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct DevInfoStruct
    {
        public VersionStruct Version;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] Manufacturer;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] Issuer;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] Label;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] SerialNumber;
        public VersionStruct HWVersion;
        public VersionStruct FirmwareVersion;
        public UInt32 AlgSymCap;
        public UInt32 AlgAsymCap;
        public UInt32 AlgHashCap;
        public UInt32 DevAuthAlgId;
        public UInt32 TotalSpace;
        public UInt32 FreeSpace;
        public UInt32 MaxECCBufferSize;
        public UInt32 MaxBufferSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] Reserved;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    public struct CflUkeyBlob
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] devName;
        public UInt32 devNameLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] tiger;
        public DevInfoStruct devInfo;
        public IntPtr hDevHandle;
        public IntPtr hApplication;
        public IntPtr hContainer;
        public IntPtr hAgreementHandle;
        public IntPtr hAgreementKeyHandle;
        public IntPtr hCipherKeyHandle;
        public IntPtr hPlainKeyHandle;
    }

    public static class Native
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetDllDirectory(string lpPathName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFL_Connect(ref UkeyParamStruct uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "CFL_Connect")]
        public static extern int CFL_ConnectBlob(ref CflUkeyBlob uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFL_Connect2(ref UkeyParamStruct uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "CFL_Connect2")]
        public static extern int CFL_Connect2Blob(ref CflUkeyBlob uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void CFL_Close(ref UkeyParamStruct uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "CFL_Close")]
        public static extern void CFL_CloseBlob(ref CflUkeyBlob uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "CFL_GenRandom")]
        public static extern int CFL_GenRandomBlob(byte[] pbRandom, UInt32 ulRandomLen, ref CflUkeyBlob uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFL_GenRandom(byte[] pbRandom, UInt32 ulRandomLen, ref UkeyParamStruct uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFL_ExportPublicKey(int bSignFlag, StringBuilder pbkx, StringBuilder pbky, ref UkeyParamStruct uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl, EntryPoint = "CFL_ExportPublicKey")]
        public static extern int CFL_ExportPublicKeyBlob(int bSignFlag, StringBuilder pbkx, StringBuilder pbky, ref CflUkeyBlob uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFL_DigestInit(IntPtr pPubKey, IntPtr pucID, UInt32 ulIDLen, out IntPtr phHash, ref UkeyParamStruct uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFL_Digest(IntPtr hHash, byte[] pbData, UInt32 ulDataLen, byte[] pbHashData, ref UInt32 pulHashLen);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFL_Sign(byte[] pbData, UInt32 ulDataLen, ref ECCSignatureBlob pSignature, ref UkeyParamStruct uks);

        [DllImport("CFLClientLib.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern int CFL_Verify(ref ECCPublicKeyBlob pECCPubKeyBlob, byte[] pbData, UInt32 ulDataLen, ref ECCSignatureBlob pSignature, ref UkeyParamStruct uks);
    }

    class Program
    {
        const int CoordinateLen = 64;
        const UInt32 PublicKeyBitLen = 256;

        static int Main(string[] args)
        {
            var serializer = new JavaScriptSerializer();
            var request = serializer.Deserialize<Dictionary<string, object>>(Console.In.ReadToEnd());
            var response = new Dictionary<string, object>();
            Native.SetDllDirectory(AppDomain.CurrentDomain.BaseDirectory);
            var uks = NewUkey(GetString(request, "pin", "123456"), GetString(request, "reader", ""));
            try
            {
                var op = GetString(request, "op");
                if (op == "status")
                {
                    var handle = Native.LoadLibrary("CFLClientLib.dll");
                    response["dll_loadable"] = handle != IntPtr.Zero;
                    response["last_error"] = handle == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
                    response["ok"] = true;
                    response["arch"] = "x86";
                    response["helper"] = "CflHelper";
                }
                else if (op == "connect2")
                {
                    Check("CFL_Connect2", Native.CFL_Connect2(ref uks));
                    response["connected"] = true;
                }
                else if (op == "connect_blob" || op == "connect2_blob" || op == "random_blob")
                {
                    var blob = NewBlob(GetString(request, "tiger", ""), GetString(request, "reader", ""));
                    var code = op == "connect2_blob" ? Native.CFL_Connect2Blob(ref blob) : Native.CFL_ConnectBlob(ref blob);
                    response["connect_code"] = code;
                    if (code != 0) throw new Exception((op == "connect2_blob" ? "CFL_Connect2Blob" : "CFL_ConnectBlob") + " failed: " + code);
                    if (op == "random_blob")
                    {
                        var length = GetInt(request, "length", 16);
                        var random = new byte[length];
                        Check("CFL_GenRandomBlob", Native.CFL_GenRandomBlob(random, (UInt32)length, ref blob));
                        response["value"] = ToHex(random);
                    }
                    response["connected"] = true;
                    try { Native.CFL_CloseBlob(ref blob); } catch { }
                }
                else if (op == "diag_export_public_key")
                {
                    var signX = new StringBuilder("0000000000000000000000000000000000000000000000000000000000000000", 65);
                    var signY = new StringBuilder("0000000000000000000000000000000000000000000000000000000000000000", 65);
                    var encX = new StringBuilder("0000000000000000000000000000000000000000000000000000000000000000", 65);
                    var encY = new StringBuilder("0000000000000000000000000000000000000000000000000000000000000000", 65);
                    var connectCode = Native.CFL_Connect(ref uks);
                    var signCode = Native.CFL_ExportPublicKey(1, signX, signY, ref uks);
                    var encCode = Native.CFL_ExportPublicKey(0, encX, encY, ref uks);
                    response["connect_code"] = connectCode;
                    response["connect_hex"] = "0x" + connectCode.ToString("X");
                    response["sign_export_code"] = signCode;
                    response["sign_export_hex"] = "0x" + signCode.ToString("X");
                    response["enc_export_code"] = encCode;
                    response["enc_export_hex"] = "0x" + encCode.ToString("X");
                    response["sign_x"] = signX.ToString();
                    response["sign_y"] = signY.ToString();
                    response["enc_x"] = encX.ToString();
                    response["enc_y"] = encY.ToString();
                }
                else if (op == "diag_export_public_key_blob")
                {
                    var blob = NewBlob(GetString(request, "tiger", ""), GetString(request, "reader", ""));
                    var signX = new StringBuilder("0000000000000000000000000000000000000000000000000000000000000000", 65);
                    var signY = new StringBuilder("0000000000000000000000000000000000000000000000000000000000000000", 65);
                    var encX = new StringBuilder("0000000000000000000000000000000000000000000000000000000000000000", 65);
                    var encY = new StringBuilder("0000000000000000000000000000000000000000000000000000000000000000", 65);
                    var connectCode = Native.CFL_ConnectBlob(ref blob);
                    var signCode = Native.CFL_ExportPublicKeyBlob(1, signX, signY, ref blob);
                    var encCode = Native.CFL_ExportPublicKeyBlob(0, encX, encY, ref blob);
                    response["connect_code"] = connectCode;
                    response["connect_hex"] = "0x" + connectCode.ToString("X");
                    response["sign_export_code"] = signCode;
                    response["sign_export_hex"] = "0x" + signCode.ToString("X");
                    response["enc_export_code"] = encCode;
                    response["enc_export_hex"] = "0x" + encCode.ToString("X");
                    response["sign_x"] = signX.ToString();
                    response["sign_y"] = signY.ToString();
                    response["enc_x"] = encX.ToString();
                    response["enc_y"] = encY.ToString();
                    try { Native.CFL_CloseBlob(ref blob); } catch { }
                }
                else
                {
                    Check("CFL_Connect", Native.CFL_Connect(ref uks));
                    if (op == "random")
                    {
                        var length = GetInt(request, "length", 32);
                        var random = new byte[length];
                        Check("CFL_GenRandom", Native.CFL_GenRandom(random, (UInt32)length, ref uks));
                        response["value"] = ToHex(random);
                    }
                    else if (op == "export_public_key")
                    {
                        var x = new StringBuilder(65);
                        var y = new StringBuilder(65);
                        Check("CFL_ExportPublicKey", Native.CFL_ExportPublicKey(1, x, y, ref uks));
                        response["x"] = x.ToString();
                        response["y"] = y.ToString();
                    }
                    else if (op == "digest")
                    {
                        response["value"] = ToHex(Digest(Convert.FromBase64String(GetString(request, "data_b64")), ref uks));
                    }
                    else if (op == "sign")
                    {
                        var digest = Digest(Convert.FromBase64String(GetString(request, "data_b64")), ref uks);
                        var sig = new ECCSignatureBlob { r = new byte[CoordinateLen], s = new byte[CoordinateLen] };
                        Check("CFL_Sign", Native.CFL_Sign(digest, (UInt32)digest.Length, ref sig, ref uks));
                        response["signature"] = ToHex(sig.r) + ToHex(sig.s);
                    }
                    else if (op == "verify")
                    {
                        var digest = Digest(Convert.FromBase64String(GetString(request, "data_b64")), ref uks);
                        var key = PublicKey(GetString(request, "public_key_x"), GetString(request, "public_key_y"));
                        var sig = Signature(GetString(request, "signature"));
                        response["valid"] = Native.CFL_Verify(ref key, digest, (UInt32)digest.Length, ref sig, ref uks) == 0;
                    }
                    else
                    {
                        throw new Exception("unknown op: " + op);
                    }
                }
                response["ok"] = true;
                Console.Write(serializer.Serialize(response));
                return 0;
            }
            catch (Exception ex)
            {
                response["ok"] = false;
                response["error"] = ex.Message;
                Console.Write(serializer.Serialize(response));
                return 1;
            }
            finally
            {
                try { Native.CFL_Close(ref uks); } catch { }
            }
        }

        static UkeyParamStruct NewUkey(string pin, string reader)
        {
            var uks = new UkeyParamStruct
            {
                hDev = IntPtr.Zero,
                hApp = IntPtr.Zero,
                hContainer = IntPtr.Zero,
                pDevName = new byte[256],
                ulDevNameLen = 256,
                ulRetryCount = 0,
                pwd = new byte[100],
                hShareKey = IntPtr.Zero,
                hAgreement = IntPtr.Zero,
                hEncKey = IntPtr.Zero
            };
            CopyAscii(pin, uks.pwd);
            CopyAscii(reader, uks.pDevName);
            if (!String.IsNullOrEmpty(reader)) uks.ulDevNameLen = (UInt32)reader.Length;
            return uks;
        }

        static CflUkeyBlob NewBlob(string tiger, string reader)
        {
            var blob = new CflUkeyBlob
            {
                devName = new byte[256],
                devNameLen = 256,
                tiger = new byte[32],
                devInfo = new DevInfoStruct
                {
                    Manufacturer = new byte[64],
                    Issuer = new byte[64],
                    Label = new byte[32],
                    SerialNumber = new byte[32],
                    Reserved = new byte[64]
                },
                hDevHandle = IntPtr.Zero,
                hApplication = IntPtr.Zero,
                hContainer = IntPtr.Zero,
                hAgreementHandle = IntPtr.Zero,
                hAgreementKeyHandle = IntPtr.Zero,
                hCipherKeyHandle = IntPtr.Zero,
                hPlainKeyHandle = IntPtr.Zero
            };
            CopyAscii(tiger, blob.tiger);
            CopyAscii(reader, blob.devName);
            if (!String.IsNullOrEmpty(reader)) blob.devNameLen = (UInt32)reader.Length;
            return blob;
        }

        static byte[] Digest(byte[] data, ref UkeyParamStruct uks)
        {
            IntPtr hash;
            Check("CFL_DigestInit", Native.CFL_DigestInit(IntPtr.Zero, IntPtr.Zero, 0, out hash, ref uks));
            var outLen = (UInt32)64;
            var output = new byte[outLen];
            Check("CFL_Digest", Native.CFL_Digest(hash, data, (UInt32)data.Length, output, ref outLen));
            Array.Resize(ref output, (int)outLen);
            return output;
        }

        static ECCPublicKeyBlob PublicKey(string x, string y)
        {
            return new ECCPublicKeyBlob { BitLen = PublicKeyBitLen, XCoordinate = FixedBytes(x), YCoordinate = FixedBytes(y) };
        }

        static ECCSignatureBlob Signature(string hex)
        {
            if (hex.Length != 128 && hex.Length != 256) throw new Exception("signature must be 128 or 256 hex chars");
            var half = hex.Length / 2;
            return new ECCSignatureBlob { r = FixedBytes(hex.Substring(0, half)), s = FixedBytes(hex.Substring(half)) };
        }

        static byte[] FixedBytes(string hex)
        {
            var raw = FromHex(hex);
            if (raw.Length > CoordinateLen) throw new Exception("hex value too long");
            var output = new byte[CoordinateLen];
            Buffer.BlockCopy(raw, 0, output, CoordinateLen - raw.Length, raw.Length);
            return output;
        }

        static void Check(string op, int code)
        {
            if (code != 0) throw new Exception(op + " failed: " + code + " (0x" + code.ToString("X") + ")");
        }

        static string GetString(Dictionary<string, object> obj, string key, string fallback = "")
        {
            if (!obj.ContainsKey(key) || obj[key] == null) return fallback;
            return Convert.ToString(obj[key]);
        }

        static int GetInt(Dictionary<string, object> obj, string key, int fallback)
        {
            if (!obj.ContainsKey(key) || obj[key] == null) return fallback;
            return Convert.ToInt32(obj[key]);
        }

        static string ToHex(byte[] data)
        {
            var sb = new StringBuilder(data.Length * 2);
            foreach (var b in data) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        static byte[] FromHex(string hex)
        {
            if (hex.Length % 2 != 0) hex = "0" + hex;
            var bytes = new byte[hex.Length / 2];
            for (var i = 0; i < bytes.Length; i++) bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        static void CopyAscii(string value, byte[] target)
        {
            var bytes = Encoding.ASCII.GetBytes(value ?? "");
            Array.Clear(target, 0, target.Length);
            Buffer.BlockCopy(bytes, 0, target, 0, Math.Min(bytes.Length, target.Length - 1));
        }
    }
}
