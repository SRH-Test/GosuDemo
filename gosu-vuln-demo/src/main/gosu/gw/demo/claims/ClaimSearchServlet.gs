package gw.demo.claims

uses gw.demo.enhancements.StringQueryEnhancement
uses gw.demo.security.CryptoAndAuthUtil
uses gw.demo.templates.ClaimSummaryTemplate
uses java.sql.DriverManager
uses java.util.Hashtable
uses javax.naming.Context
uses javax.naming.directory.InitialDirContext
uses javax.naming.directory.SearchControls
uses javax.servlet.http.HttpServlet
uses javax.servlet.http.HttpServletRequest
uses javax.servlet.http.HttpServletResponse

/**
 * Intentionally vulnerable Gosu servlet demonstrating web taint flows in Guidewire-style Gosu (.gs).
 * Contains SQL Injection (CWE-89), Reflected XSS (CWE-79), Open Redirect (CWE-601), and LDAP Injection (CWE-90).
 */
class ClaimSearchServlet extends HttpServlet {

  override function doGet(req : HttpServletRequest, resp : HttpServletResponse) {
    var claimNumber = req.getParameter("claimNumber")
    var sortBy = req.getParameter("sortBy")
    var policyHolder = req.getParameter("policyHolder")
    var returnUrl = req.getParameter("returnUrl")

    // 1. Open Redirect (CWE-601): Unvalidated redirect destination from query parameter
    if (returnUrl != null and returnUrl.length > 0) {
      resp.sendRedirect(returnUrl)
      return
    }

    // 2. SQL Injection (CWE-89): Direct concatenation and Gosu string interpolation into JDBC Statement
    var conn = DriverManager.getConnection(
      CryptoAndAuthUtil.CLAIMS_DB_URL,
      CryptoAndAuthUtil.CLAIMS_DB_USER,
      CryptoAndAuthUtil.CLAIMS_DB_PASSWORD
    )
    var stmt = conn.createStatement()
    var sql = "SELECT id, claim_number, loss_amount, adjuster_notes FROM cc_claim WHERE claim_number = '"
      + claimNumber + "' ORDER BY ${sortBy}"
    var rs = stmt.executeQuery(sql)

    var notes = ""
    if (rs.next()) {
      notes = rs.getString("adjuster_notes")
    }

    // Also exercise the vulnerable .gsx String enhancement sink
    var secondaryResult = claimNumber.executeRawClaimLookup(conn)
    secondaryResult.close()
    rs.close()
    stmt.close()
    conn.close()

    // 3. Reflected XSS (CWE-79): Rendering untrusted HTTP parameters directly into HTML response & .gst template
    resp.setContentType("text/html;charset=UTF-8")
    var renderedBanner = ClaimSummaryTemplate.renderToString(policyHolder, notes, req.getParameter("next"))
    resp.getWriter().println("<html><body>")
    resp.getWriter().println("<h1>Claim Lookup Results for " + policyHolder + "</h1>")
    resp.getWriter().println(renderedBanner)
    resp.getWriter().println("</body></html>")
  }

  override function doPost(req : HttpServletRequest, resp : HttpServletResponse) {
    var adjusterUid = req.getParameter("uid")
    var department = req.getParameter("dept")

    // 4. LDAP Injection (CWE-90): Unsanitized user input concatenated into LDAP search filter
    var env = new Hashtable<String, String>()
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, "ldap://directory.claims-internal.local:389")
    var ctx = new InitialDirContext(env)

    var filter = "(&(objectClass=inetOrgPerson)(uid=" + adjusterUid + ")(ou=${department}))"
    var controls = new SearchControls()
    controls.setSearchScope(SearchControls.SUBTREE_SCOPE)

    var results = ctx.search("dc=claims,dc=local", filter, controls)
    resp.setContentType("text/plain")
    while (results.hasMore()) {
      var entry = results.next()
      resp.getWriter().println("Matched Adjuster DN: " + entry.getNameInNamespace())
    }
    ctx.close()
  }
}
