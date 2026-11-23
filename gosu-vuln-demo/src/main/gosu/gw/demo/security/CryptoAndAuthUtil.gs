package gw.demo.security

uses java.nio.charset.StandardCharsets
uses java.security.MessageDigest
uses java.security.SecureRandom
uses java.security.cert.X509Certificate
uses java.util.Base64
uses java.util.Random
uses javax.crypto.Cipher
uses javax.crypto.spec.SecretKeySpec
uses javax.net.ssl.HttpsURLConnection
uses javax.net.ssl.SSLContext
uses javax.net.ssl.TrustManager
uses javax.net.ssl.X509TrustManager

/**
 * Intentionally vulnerable Gosu authentication & cryptography helper (.gs).
 * Contains hardcoded credentials/API keys (CWE-798), broken crypto (CWE-327/CWE-328),
 * insecure PRNG (CWE-330), and disabled TLS certificate validation (CWE-295).
 */
class CryptoAndAuthUtil {

  // 1. Hardcoded Secrets & Credentials (CWE-798 / Secret Scanner Findings)
  public static final var CLAIMS_DB_URL : String = "jdbc:postgresql://claims-db.prod.internal:5432/claimcenter"
  public static final var CLAIMS_DB_URI : String = "postgresql://cc_prod_admin:Zp9xK4mN8qR2vL7wT5yB@claims-db.prod.internal:5432/claimcenter"
  public static final var CLAIMS_DB_USER : String = "cc_prod_admin"
  public static final var CLAIMS_DB_PASSWORD : String = "Zp9xK4mN8qR2vL7wT5yB!2026"

  public static final var AWS_ACCESS_KEY_ID : String = "AKIAQ7X9M2P4L8K3V6NR"
  public static final var AWS_SECRET_ACCESS_KEY : String = "r8Km3Pq9Vz4Lw7Xn2Tb6Yf5Hj8Dc1Ns4Qa9We2Zr"
  public static final var JWT_SIGNING_SECRET : String = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e"
  public static final var INTERNAL_BEARER_TOKEN : String = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJjY19hZG1pbiIsInJvbGUiOiJzdXBlcnVzZXIiLCJpYXQiOjE3MzIzNzI4MDB9.K8vM2xP9qL4nR7wT3zY6bF1cH5jD8sA2eG4kU9oI0pQ"

  // 2. Weak Password Hashing (CWE-328): Unsalted MD5 & SHA-1
  public static function hashClaimantPasswordMd5(password : String) : String {
    var md = MessageDigest.getInstance("MD5")
    var digest = md.digest(password.getBytes(StandardCharsets.UTF_8))
    return Base64.getEncoder().encodeToString(digest)
  }

  public static function hashApiTokenSha1(token : String) : String {
    var sha1 = MessageDigest.getInstance("SHA-1")
    return Base64.getEncoder().encodeToString(sha1.digest(token.getBytes(StandardCharsets.UTF_8)))
  }

  // 3. Broken / Weak Symmetric Encryption (CWE-327): DES and AES-ECB with hardcoded key
  public static function encryptSsnWithDes(ssn : String) : String {
    var rawKey = "8ByteKey".getBytes(StandardCharsets.UTF_8)
    var keySpec = new SecretKeySpec(rawKey, "DES")
    var cipher = Cipher.getInstance("DES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec)
    var encrypted = cipher.doFinal(ssn.getBytes(StandardCharsets.UTF_8))
    return Base64.getEncoder().encodeToString(encrypted)
  }

  // 4. Insecure Randomness (CWE-330): Predictable java.util.Random for password reset tokens
  public static function generatePasswordResetToken() : String {
    var rng = new Random()
    return "reset-" + rng.nextLong()
  }

  // 5. Improper Certificate Validation (CWE-295): Trust-all X509TrustManager & HostnameVerifier
  public static function disableTlsVerificationGlobally() {
    var trustAll = new TrustManager[] {
      new X509TrustManager() {
        override function checkClientTrusted(chain : X509Certificate[], authType : String) {}
        override function checkServerTrusted(chain : X509Certificate[], authType : String) {}
        override function getAcceptedIssuers() : X509Certificate[] {
          return new X509Certificate[0]
        }
      }
    }

    var sslContext = SSLContext.getInstance("TLS")
    sslContext.init(null, trustAll, new SecureRandom())
    HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory())
    HttpsURLConnection.setDefaultHostnameVerifier(\ hostname, session -> true)
  }
}
