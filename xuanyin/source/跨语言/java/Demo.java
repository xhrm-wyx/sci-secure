import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * 跨语言互通验证程序（Java）
 *
 * 用法：
 *   javac -encoding UTF-8 SciSecure.java Demo.java
 *   java Demo envelope.json "CrossLang-测试123"
 *
 * 预期：打印三级派生中间值（应与 test_vectors.json 完全一致）与解密出的明文。
 */
public class Demo {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.out.println("用法: java Demo <envelope.json> <密码>");
            return;
        }
        String json = new String(Files.readAllBytes(Paths.get(args[0])), StandardCharsets.UTF_8);
        String password = args[1];

        String accountSalt = SciSecure.fieldStr(json, "accountSalt");
        String salt        = SciSecure.fieldStr(json, "salt");
        long iterations    = SciSecure.fieldLong(json, "iterations", 600000);

        byte[] ikm     = SciSecure.pbkdf2(password, SciSecure.b64d(accountSalt), (int) iterations);
        byte[] session = SciSecure.hkdf(ikm, null, "sci-session-v1", 32);
        byte[] fileKey = SciSecure.hkdf(session, SciSecure.b64d(salt), "sci-file-v4", 32);

        System.out.println("IKM       : " + SciSecure.hex(ikm));
        System.out.println("sessionKey: " + SciSecure.hex(session));
        System.out.println("fileKey   : " + SciSecure.hex(fileKey));

        String plain = SciSecure.decryptV4(json, password);
        byte[] plainBytes = plain.getBytes(StandardCharsets.UTF_8);
        Files.write(Paths.get("out.txt"), plainBytes);
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        System.out.println("plainLen  : " + plainBytes.length);
        System.out.println("plainSha  : " + SciSecure.hex(md.digest(plainBytes)));
        System.out.println("plaintext : " + plain);

        // 再验证一次加密：自己生成的信封，自己能解开
        String env2 = SciSecure.encryptV4("{\"roundtrip\":\"java\",\"n\":7}", password, "java-demo", 600000);
        Files.write(Paths.get("roundtrip_envelope.json"), env2.getBytes(StandardCharsets.UTF_8));
        String back = SciSecure.decryptV4(env2, password);
        System.out.println("roundtrip : " + back);
        System.out.println("OK        : " + ("{\"roundtrip\":\"java\",\"n\":7}".equals(back) ? "true" : "false"));
    }
}
