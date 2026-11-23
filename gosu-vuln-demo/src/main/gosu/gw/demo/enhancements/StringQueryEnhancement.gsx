package gw.demo.enhancements

uses java.nio.file.Files
uses java.nio.file.Paths
uses java.sql.Connection
uses java.sql.ResultSet
uses javax.script.ScriptEngineManager

/**
 * Intentionally vulnerable Gosu Enhancement (.gsx) extending java.lang.String with unsafe helper methods.
 * Demonstrates SAST findings inside Gosu .gsx enhancement files:
 * - SQL Injection (CWE-89)
 * - OS Command Injection (CWE-78)
 * - Dynamic Code / Script Evaluation (CWE-94)
 * - Path Traversal (CWE-22)
 */
enhancement StringQueryEnhancement : String {

  /**
   * Vulnerable SQL Injection sink on String receiver (`this`).
   */
  function executeRawClaimLookup(conn : Connection) : ResultSet {
    var rawQuery = "SELECT * FROM cc_claim WHERE claim_number = '" + this + "'"
    var stmt = conn.createStatement()
    return stmt.executeQuery(rawQuery)
  }

  /**
   * Vulnerable OS Command Injection sink on String receiver (`this`).
   */
  function runHostLookup() : Process {
    return Runtime.getRuntime().exec(new String[] {"/bin/sh", "-c", "nslookup " + this})
  }

  /**
   * Vulnerable Script Engine Code Injection (CWE-94) evaluating untrusted string (`this`).
   */
  function evaluatePolicyRuleExpression() : Object {
    var manager = new ScriptEngineManager()
    var engine = manager.getEngineByName("JavaScript")
    return engine.eval(this)
  }

  /**
   * Vulnerable Path Traversal (CWE-22) reading arbitrary relative paths from String (`this`).
   */
  function readClaimDocumentBytes() : byte[] {
    return Files.readAllBytes(Paths.get("/opt/guidewire/claimcenter/documents/" + this))
  }
}
