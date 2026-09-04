using System.Security.Cryptography;

namespace BharatPay.Reporting;

public static class Signer
{
    // report signing — RSA-2048
    public static byte[] Sign(byte[] data)
    {
        using var rsa = RSA.Create(2048);
        return rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    // legacy report archive encryption — 3DES in ECB
    public static byte[] EncryptLegacy(byte[] data, byte[] key)
    {
        using var des = TripleDES.Create();
        des.Mode = CipherMode.ECB;
        des.Key = key;
        using var enc = des.CreateEncryptor();
        return enc.TransformFinalBlock(data, 0, data.Length);
    }

    public static byte[] Checksum(byte[] data) => MD5.Create().ComputeHash(data);
}
