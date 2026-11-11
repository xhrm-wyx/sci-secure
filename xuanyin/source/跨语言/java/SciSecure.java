import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * SciSecure —— 玄印（sci-secure）v4 信封的 Java 实现（纯 JDK，无第三方依赖）
 *
 * 与 JavaScript 版 sci-secure-core.js 完全互通：
 *   IKM        = PBKDF2-HMAC-SHA256(password, accountSalt, iterations, 32)
 *   sessionKey = HKDF-SHA256(IKM,        salt=空,      info="sci-session-v1", 32)
 *   fileKey    = HKDF-SHA256(sessionKey, salt=文件盐,  info="sci-file-v4",   32)
 *   AAD        = 固定键序的元数据 JSON（见 buildAad）
 *   密文       = AES-256-GCM(fileKey, iv, plaintext, AAD)，输出 密文||16字节tag
 *
 * 环境要求：JDK 8+（PBKDF2WithHmacSHA256 需要 JDK 8 及以上）
 */
public final class SciSecure {

    private static final int TAG_BITS = 128;
    private static final SecureRandom RNG = new SecureRandom();

    private SciSecure() {}

    /* ---------------- 基础派生 ---------------- */

    public static byte[] pbkdf2(String password, byte[] salt, int iterations) throws Exception {
        if (iterations < 50000) iterations = 50000;
        if (iterations > 1000000) iterations = 1000000;
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
        return f.generateSecret(spec).getEncoded();
    }

    /** RFC 5869 HKDF-SHA256；salt 为空时按规范使用 HashLen 个 0 字节 */
    public static byte[] hkdf(byte[] ikm, byte[] salt, String info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        byte[] saltUse = (salt == null || salt.length == 0) ? new byte[32] : salt;
        mac.init(new SecretKeySpec(saltUse, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);

        byte[] infoBytes = info.getBytes(StandardCharsets.UTF_8);
        byte[] t = new byte[infoBytes.length + 1];
        System.arraycopy(infoBytes, 0, t, 0, infoBytes.length);
        t[infoBytes.length] = 0x01;

        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        byte[] okm = mac.doFinal(t);              // 32 字节足够（本方案只取 32）
        if (length == 32) return okm;
        byte[] out = new byte[length];
        System.arraycopy(okm, 0, out, 0, length);
        return out;
    }

    /* ---------------- 解密 v4 ---------------- */

    public static String decryptV4(String envelopeJson, String password) throws Exception {
        String username    = getStr(envelopeJson, "username");
        String accountSalt = getStr(envelopeJson, "accountSalt");
        String salt        = getStr(envelopeJson, "salt");
        String iv          = getStr(envelopeJson, "iv");
        String data        = getStr(envelopeJson, "data");
        long iterations    = getLong(envelopeJson, "iterations", 600000);
        long savedAt       = getLong(envelopeJson, "savedAt", 0);
        if (username == null) username = "";

        byte[] ikm      = pbkdf2(password, b64d(accountSalt), (int) iterations);
        byte[] session  = hkdf(ikm, null, "sci-session-v1", 32);
        byte[] fileKey  = hkdf(session, b64d(salt), "sci-file-v4", 32);

        String aad = buildAad(4, username, accountSalt, salt, iv, iterations, savedAt);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(fileKey, "AES"),
               new GCMParameterSpec(TAG_BITS, b64d(iv)));
        c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        byte[] pt = c.doFinal(b64d(data));        // Java 的 GCM 会自行剥离末尾 16 字节 tag
        return new String(pt, StandardCharsets.UTF_8);
    }

    /* ---------------- 加密 v4 ---------------- */

    public static String encryptV4(String plaintext, String password, String username, long iterations) throws Exception {
        if (iterations <= 0) iterations = 600000;
        if (iterations < 50000) iterations = 50000;
        if (iterations > 1000000) iterations = 1000000;
        if (username == null) username = "";

        byte[] acctSalt = new byte[16];
        byte[] fileSalt = new byte[32];
        byte[] iv       = new byte[12];
        RNG.nextBytes(acctSalt);
        RNG.nextBytes(fileSalt);
        RNG.nextBytes(iv);

        String acctB64 = b64e(acctSalt);
        String saltB64 = b64e(fileSalt);
        String ivB64   = b64e(iv);
        long savedAt   = System.currentTimeMillis();

        byte[] ikm     = pbkdf2(password, acctSalt, (int) iterations);
        byte[] session = hkdf(ikm, null, "sci-session-v1", 32);
        byte[] fileKey = hkdf(session, fileSalt, "sci-file-v4", 32);

        String aad = buildAad(4, username, acctB64, saltB64, ivB64, iterations, savedAt);

        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(fileKey, "AES"),
               new GCMParameterSpec(TAG_BITS, iv));
        c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));
        byte[] ct = c.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));   // 含 16 字节 tag

        // aad 形如 {...}，把末尾的 } 换成 ,"data":"..."}
        return aad.substring(0, aad.length() - 1)
             + ",\"data\":\"" + b64e(ct) + "\"}";
    }

    /* ---------------- AAD（键序固定，勿改） ---------------- */

    private static String buildAad(int v, String username, String accountSalt,
                                   String salt, String iv, long iterations, long savedAt) {
        return "{\"v\":" + v
             + ",\"username\":\"" + esc(username) + "\""
             + ",\"accountSalt\":\"" + accountSalt + "\""
             + ",\"salt\":\"" + salt + "\""
             + ",\"iv\":\"" + iv + "\""
             + ",\"iterations\":" + iterations
             + ",\"savedAt\":" + savedAt + "}";
    }

    /* ---------------- 工具 ---------------- */

    public static String b64e(byte[] b) { return Base64.getEncoder().encodeToString(b); }
    public static byte[] b64d(String s) { return Base64.getDecoder().decode(s); }
    public static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /* 供外部（如测试程序）读取信封字段 */
    public static String fieldStr(String json, String key) { return getStr(json, key); }
    public static long fieldLong(String json, String key, long defv) { return getLong(json, key, defv); }

    private static String esc(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (ch < 0x20) sb.append(String.format("\\u%04x", (int) ch));
                    else sb.append(ch);
            }
        }
        return sb.toString();
    }

    private static String getStr(String json, String key) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");
        Matcher m = p.matcher(json);
        if (!m.find()) return null;
        return unesc(m.group(1));
    }

    private static long getLong(String json, String key, long defv) {
        Pattern p = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)");
        Matcher m = p.matcher(json);
        if (!m.find()) return defv;
        return Long.parseLong(m.group(1));
    }

    private static String unesc(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch != '\\') { sb.append(ch); continue; }
            i++;
            if (i >= s.length()) break;
            char n = s.charAt(i);
            switch (n) {
                case 'n': sb.append('\n'); break;
                case 'r': sb.append('\r'); break;
                case 't': sb.append('\t'); break;
                case 'b': sb.append('\b'); break;
                case 'f': sb.append('\f'); break;
                case 'u':
                    sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                    i += 4;
                    break;
                default: sb.append(n);
            }
        }
        return sb.toString();
    }
}
