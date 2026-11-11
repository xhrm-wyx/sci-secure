// 玄印（sci-secure）v4 信封跨语言实现（C# / .NET 8 版）
//
// 与 JavaScript 版 sci-secure-core.js 完全互通：
//   IKM        = PBKDF2-HMAC-SHA256(password, accountSalt, iterations, 32)
//   sessionKey = HKDF-SHA256(IKM,        salt=空,     info="sci-session-v1", 32)
//   fileKey    = HKDF-SHA256(sessionKey, salt=文件盐, info="sci-file-v4",    32)
//   AAD        = 固定键序的元数据 JSON
//   密文        = AES-256-GCM(fileKey, iv, plaintext, AAD)，输出 密文||16字节tag
//
// 依赖：仅 .NET 8 基础类库（System.Security.Cryptography / System.Text.Json），零第三方包。

using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SciSecure;

/// <summary>v4 信封字段定义。JSON 键序即属性声明序，与 AAD 构造严格一致。</summary>
public sealed class Envelope
{
    [JsonPropertyName("v")] public int V { get; set; }
    [JsonPropertyName("username")] public string Username { get; set; } = "";
    [JsonPropertyName("accountSalt")] public string AccountSalt { get; set; } = "";
    [JsonPropertyName("salt")] public string Salt { get; set; } = "";
    [JsonPropertyName("iv")] public string Iv { get; set; } = "";
    [JsonPropertyName("iterations")] public int Iterations { get; set; }
    [JsonPropertyName("savedAt")] public long SavedAt { get; set; }
    [JsonPropertyName("data")] public string Data { get; set; } = "";
}

internal sealed class AadPayload
{
    [JsonPropertyName("v")] public int V { get; set; }
    [JsonPropertyName("username")] public string Username { get; set; } = "";
    [JsonPropertyName("accountSalt")] public string AccountSalt { get; set; } = "";
    [JsonPropertyName("salt")] public string Salt { get; set; } = "";
    [JsonPropertyName("iv")] public string Iv { get; set; } = "";
    [JsonPropertyName("iterations")] public int Iterations { get; set; }
    [JsonPropertyName("savedAt")] public long SavedAt { get; set; }
}

public sealed class SciSecureException : Exception
{
    public SciSecureException(string message) : base(message) { }
}

public static class SciSecure
{
    public const int MinIterations = 50_000;
    public const int MaxIterations = 1_000_000;
    public const int DefaultIterations = 600_000;
    public const int TagLen = 16;
    public const int KeyLen = 32;

    // UnsafeRelaxedJsonEscaping：不转义 <、>、& 与非 ASCII，与 JavaScript JSON.stringify 行为一致
    private static readonly JsonSerializerOptions AadOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
    };

    public static int ClampIterations(int n) => Math.Clamp(n, MinIterations, MaxIterations);

    /// <summary>构造 AAD：固定键序的元数据 JSON，不含 data 字段。</summary>
    public static byte[] BuildAad(string username, string accountSalt, string salt, string iv,
                                  int iterations, long savedAt)
    {
        var payload = new AadPayload
        {
            V = 4,
            Username = username,
            AccountSalt = accountSalt,
            Salt = salt,
            Iv = iv,
            Iterations = iterations,
            SavedAt = savedAt,
        };
        return JsonSerializer.SerializeToUtf8Bytes(payload, AadOptions);
    }

    /// <summary>三级派生，返回 (ikm, sessionKey, fileKey)。</summary>
    public static (byte[] Ikm, byte[] SessionKey, byte[] FileKey) DeriveKeys(
        string password, string accountSaltB64, int iterations, string fileSaltB64)
    {
        byte[] acctSalt, fileSalt;
        try
        {
            acctSalt = Convert.FromBase64String(accountSaltB64);
            fileSalt = Convert.FromBase64String(fileSaltB64);
        }
        catch (FormatException e)
        {
            throw new SciSecureException("盐不是合法 base64: " + e.Message);
        }

        int it = ClampIterations(iterations);

        byte[] ikm = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password), acctSalt, it, HashAlgorithmName.SHA256, KeyLen);

        byte[] session = HKDF.DeriveKey(
            HashAlgorithmName.SHA256, ikm, KeyLen,
            salt: Array.Empty<byte>(),
            info: Encoding.UTF8.GetBytes("sci-session-v1"));

        byte[] fileKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256, session, KeyLen,
            salt: fileSalt,
            info: Encoding.UTF8.GetBytes("sci-file-v4"));

        return (ikm, session, fileKey);
    }

    /// <summary>解析信封 JSON；版本必须是 v4。</summary>
    public static Envelope ParseEnvelope(string json)
    {
        Envelope? env;
        try
        {
            env = JsonSerializer.Deserialize<Envelope>(json);
        }
        catch (JsonException e)
        {
            throw new SciSecureException("信封 JSON 解析失败: " + e.Message);
        }
        if (env is null) throw new SciSecureException("信封 JSON 为空");
        if (env.V != 4) throw new SciSecureException($"不支持的信封版本 v{env.V}（本实现仅支持 v4）");
        return env;
    }

    /// <summary>解密 v4 信封，返回明文字节。认证失败抛 SciSecureException。</summary>
    public static byte[] DecryptV4(Envelope env, string password)
    {
        if (env.V != 4) throw new SciSecureException($"不支持的信封版本 v{env.V}（本实现仅支持 v4）");

        var (_, _, fileKey) = DeriveKeys(password, env.AccountSalt, env.Iterations, env.Salt);

        byte[] iv, blob;
        try
        {
            iv = Convert.FromBase64String(env.Iv);
            blob = Convert.FromBase64String(env.Data);
        }
        catch (FormatException e)
        {
            throw new SciSecureException("iv/data 不是合法 base64: " + e.Message);
        }
        if (iv.Length != 12) throw new SciSecureException($"iv 应为 12 字节，实际 {iv.Length}");
        if (blob.Length < TagLen) throw new SciSecureException("密文长度不足，缺少认证标签");

        byte[] aad = BuildAad(env.Username, env.AccountSalt, env.Salt, env.Iv, env.Iterations, env.SavedAt);

        int ctLen = blob.Length - TagLen;
        byte[] ciphertext = blob.AsSpan(0, ctLen).ToArray();
        byte[] tag = blob.AsSpan(ctLen, TagLen).ToArray();
        byte[] plain = new byte[ctLen];

        using var gcm = new AesGcm(fileKey, TagLen);
        try
        {
            gcm.Decrypt(iv, ciphertext, tag, plain, aad);
        }
        catch (CryptographicException)
        {
            throw new SciSecureException("认证失败：密码错误或数据已被篡改");
        }
        return plain;
    }

    /// <summary>便捷函数：信封 JSON 文本 + 密码 → 明文。</summary>
    public static byte[] DecryptV4Json(string envelopeJson, string password)
        => DecryptV4(ParseEnvelope(envelopeJson), password);

    /// <summary>加密为 v4 信封 JSON（缩进两格）。iterations &lt;= 0 时用 600000。</summary>
    public static string EncryptV4(byte[] plain, string password, string username, int iterations)
        => EncryptV4At(plain, password, username, iterations, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());

    /// <summary>同 EncryptV4，但可指定 savedAt（毫秒），便于生成可复现向量。</summary>
    public static string EncryptV4At(byte[] plain, string password, string username,
                                     int iterations, long savedAt)
    {
        int it = iterations <= 0 ? DefaultIterations : ClampIterations(iterations);

        byte[] acctSalt = RandomNumberGenerator.GetBytes(16);
        byte[] fileSalt = RandomNumberGenerator.GetBytes(32);
        byte[] iv = RandomNumberGenerator.GetBytes(12);

        string acctB64 = Convert.ToBase64String(acctSalt);
        string saltB64 = Convert.ToBase64String(fileSalt);
        string ivB64 = Convert.ToBase64String(iv);

        var (_, _, fileKey) = DeriveKeys(password, acctB64, it, saltB64);
        byte[] aad = BuildAad(username, acctB64, saltB64, ivB64, it, savedAt);

        byte[] ciphertext = new byte[plain.Length];
        byte[] tag = new byte[TagLen];
        using (var gcm = new AesGcm(fileKey, TagLen))
        {
            gcm.Encrypt(iv, plain, ciphertext, tag, aad);
        }

        byte[] sealedBlob = new byte[plain.Length + TagLen];
        Buffer.BlockCopy(ciphertext, 0, sealedBlob, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, sealedBlob, ciphertext.Length, TagLen);

        var env = new Envelope
        {
            V = 4,
            Username = username,
            AccountSalt = acctB64,
            Salt = saltB64,
            Iv = ivB64,
            Iterations = it,
            SavedAt = savedAt,
            Data = Convert.ToBase64String(sealedBlob),
        };

        return JsonSerializer.Serialize(env, new JsonSerializerOptions { WriteIndented = true });
    }
}
