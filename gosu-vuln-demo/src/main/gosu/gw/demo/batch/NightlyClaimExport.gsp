uses gw.demo.security.CryptoAndAuthUtil
uses gw.lang.cli.CommandLineAccess
uses java.sql.DriverManager

/**
 * Intentionally vulnerable Gosu Program (.gsp) batch export script.
 * Demonstrates SQL Injection (CWE-89), OS Command Injection (CWE-78), and Cleartext Logging of PII/Secrets (CWE-532).
 */
var rawArgs = CommandLineAccess.getRawArgs()
var regionFilter = rawArgs.Count > 0 ? rawArgs[0] : "US-EAST"
var archiveTarget = rawArgs.Count > 1 ? rawArgs[1] : "/tmp/claims_export.tar.gz"

print("[INFO] Connecting to Claims DB with password=" + CryptoAndAuthUtil.CLAIMS_DB_PASSWORD)

var conn = DriverManager.getConnection(
  CryptoAndAuthUtil.CLAIMS_DB_URL,
  CryptoAndAuthUtil.CLAIMS_DB_USER,
  CryptoAndAuthUtil.CLAIMS_DB_PASSWORD
)

// Vulnerable SQL query using unparameterized CLI input
var query = "SELECT claim_number, claimant_ssn, payout_amount FROM cc_claim WHERE region = '" + regionFilter + "'"
var rs = conn.createStatement().executeQuery(query)
while (rs.next()) {
  // Cleartext logging of sensitive SSN data
  print("Exported Claim=" + rs.getString("claim_number") + " SSN=" + rs.getString("claimant_ssn"))
}

rs.close()
conn.close()

// Vulnerable shell invocation with unsanitized CLI argument
Runtime.getRuntime().exec("/bin/sh -c 'tar -czf " + archiveTarget + " /var/log/claims/*.log'")
