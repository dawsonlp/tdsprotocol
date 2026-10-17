// The driver's local key store (tds/encryption/keys.py), for SqlClient. Master keys are RSA private keys in PEM files
// in one directory, and a key path is a file name in that directory. The encrypted column key has the layout that SQL
// Server's tools write: version, key path length, ciphertext length, key path, RSA-OAEP (SHA-1) ciphertext, then an
// RSA PKCS#1 v1.5 SHA-256 signature over all the bytes before it.
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.SqlClient;

sealed class LocalKeys(string directory) : SqlColumnEncryptionKeyStoreProvider
{
    public const string Name = "TDS_LOCAL_KEYS";

    RSA Key(string path)
    {
        var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(Path.Combine(directory, path)));
        return rsa;
    }

    public override byte[] DecryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] encrypted)
    {
        using var rsa = Key(masterKeyPath);
        int pathLength = BitConverter.ToUInt16(encrypted, 1), cipherLength = BitConverter.ToUInt16(encrypted, 3);
        int start = 5 + pathLength;
        byte[] body = encrypted[..(start + cipherLength)], signature = encrypted[(start + cipherLength)..];
        if (!rsa.VerifyData(body, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            throw new CryptographicException($"the column key's signature doesn't verify with {masterKeyPath}");
        return rsa.Decrypt(encrypted[start..(start + cipherLength)], RSAEncryptionPadding.OaepSHA1);
    }

    public override byte[] EncryptColumnEncryptionKey(string masterKeyPath, string encryptionAlgorithm, byte[] key)
    {
        using var rsa = Key(masterKeyPath);
        byte[] path = Encoding.Unicode.GetBytes(masterKeyPath), cipher = rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA1);
        byte[] body = [1, .. BitConverter.GetBytes((ushort)path.Length), .. BitConverter.GetBytes((ushort)cipher.Length), .. path, .. cipher];
        return [.. body, .. rsa.SignData(body, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)];
    }
}
