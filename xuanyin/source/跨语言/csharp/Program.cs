// demo — 跨语言互通验证（C# / .NET 8 版）
//
// 用法：
//   dotnet run -- ../envelope.json "CrossLang-测试123"
//   dotnet run -- ../envelope.json "hex:43726f73..."

using System.Security.Cryptography;
using System.Text;
using SciSecure;

Console.OutputEncoding = Encoding.UTF8;

static string HexLower(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

if (args.Length < 2)
{
    Console.WriteLine("用法: demo <envelope.json> <密码|hex:...>");
    return 1;
}

static string DecodePassword(string arg)
{
    if (!arg.StartsWith("hex:", StringComparison.Ordinal)) return arg;
    string h = arg.Substring(4);
    byte[] bytes = Convert.FromHexString(h);
    return Encoding.UTF8.GetString(bytes);
}

string json = File.ReadAllText(args[0], Encoding.UTF8);
string password = DecodePassword(args[1]);

var env = SciSecure.SciSecure.ParseEnvelope(json);

var (ikm, session, fileKey) = SciSecure.SciSecure.DeriveKeys(
    password, env.AccountSalt, env.Iterations, env.Salt);

Console.WriteLine($"ikm       : {HexLower(ikm)}");
Console.WriteLine($"sessionKey: {HexLower(session)}");
Console.WriteLine($"fileKey   : {HexLower(fileKey)}");

byte[] plain;
try
{
    plain = SciSecure.SciSecure.DecryptV4(env, password);
}
catch (SciSecureException e)
{
    Console.WriteLine($"解密失败: {e.Message}");
    return 4;
}

Console.WriteLine($"plainLen  : {plain.Length}");
Console.WriteLine($"plainSha  : {HexLower(SHA256.HashData(plain))}");
File.WriteAllBytes("out.txt", plain);
Console.WriteLine($"plaintext : {Encoding.UTF8.GetString(plain)}");

const string want = "{\"roundtrip\":\"csharp\",\"n\":7}";
string env2 = SciSecure.SciSecure.EncryptV4(
    Encoding.UTF8.GetBytes(want), password, "csharp-demo", 600_000);
File.WriteAllText("roundtrip_envelope.json", env2, new UTF8Encoding(false));

byte[] back = SciSecure.SciSecure.DecryptV4Json(env2, password);
Console.WriteLine($"roundtrip : {Encoding.UTF8.GetString(back)}");
Console.WriteLine($"OK        : {Encoding.UTF8.GetString(back) == want}");
return 0;
