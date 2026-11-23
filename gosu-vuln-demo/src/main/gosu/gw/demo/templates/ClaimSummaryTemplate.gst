<%@ params(policyHolder : String, claimNotes : String, redirectTarget : String) %>
<!--
  Intentionally vulnerable Gosu String Template (.gst).
  Renders unescaped user input directly into HTML markup and inline JavaScript (CWE-79 XSS, CWE-601 Open Redirect).
-->
<div class="claim-summary-card">
  <h2>Policyholder: ${policyHolder}</h2>
  <div class="adjuster-notes">
    <% print(claimNotes) %>
  </div>
  <% if (redirectTarget != null and redirectTarget.length > 0) { %>
    <script type="text/javascript">
      var nextDestination = "${redirectTarget}";
      if (nextDestination) {
        document.write("<p>Redirecting to " + nextDestination + "...</p>");
        window.location.href = nextDestination;
      }
    </script>
  <% } %>
</div>
