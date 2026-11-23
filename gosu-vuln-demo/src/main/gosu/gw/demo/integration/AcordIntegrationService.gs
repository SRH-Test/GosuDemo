package gw.demo.integration

uses java.io.ByteArrayInputStream
uses java.io.File
uses java.io.FileInputStream
uses java.io.ObjectInputStream
uses java.net.HttpURLConnection
uses java.net.URL
uses java.nio.file.Files
uses java.nio.file.Paths
uses javax.servlet.http.HttpServlet
uses javax.servlet.http.HttpServletRequest
uses javax.servlet.http.HttpServletResponse
uses javax.xml.parsers.DocumentBuilderFactory
uses javax.xml.transform.TransformerFactory
uses javax.xml.transform.dom.DOMSource
uses javax.xml.transform.stream.StreamResult
uses org.yaml.snakeyaml.Yaml

/**
 * Intentionally vulnerable Gosu integration handler (.gs) simulating Guidewire ACORD XML,
 * attachment retrieval, webhook callbacks, PDF conversion, and payload deserialization.
 */
class AcordIntegrationService extends HttpServlet {

  override function doPost(req : HttpServletRequest, resp : HttpServletResponse) {
    var action = req.getParameter("action")

    if (action == "acordXml") {
      // 1. XML External Entity (XXE - CWE-611): Default DocumentBuilderFactory allows external DTDs/entities
      var rawXml = req.getParameter("xmlPayload")
      var dbf = DocumentBuilderFactory.newInstance()
      var builder = dbf.newDocumentBuilder()
      var doc = builder.parse(new ByteArrayInputStream(rawXml.Bytes))

      var tf = TransformerFactory.newInstance()
      tf.newTransformer().transform(new DOMSource(doc), new StreamResult(resp.getOutputStream()))

    } else if (action == "convertPdf") {
      // 2. OS Command Injection (CWE-78): Unsanitized filename concatenated into shell command
      var attachmentName = req.getParameter("file")
      var cmd = "/bin/sh -c 'gs -sDEVICE=pdfwrite -o /tmp/out.pdf /var/claims/uploads/" + attachmentName + "'"
      var proc = Runtime.getRuntime().exec(cmd)
      proc.waitFor()

      // Secondary command injection via ProcessBuilder
      var pb = new ProcessBuilder({"sh", "-c", "exiftool " + attachmentName})
      pb.start()

    } else if (action == "webhook") {
      // 3. Server-Side Request Forgery (SSRF - CWE-918): Fetching attacker-controlled URL directly
      var callbackUrl = req.getParameter("callbackUrl")
      var target = new URL(callbackUrl)
      var conn = target.openConnection() as HttpURLConnection
      conn.setRequestMethod("GET")
      var body = conn.getInputStream().readAllBytes()
      resp.getOutputStream().write(body)

    } else if (action == "deserialize") {
      // 4. Insecure Deserialization (CWE-502): Java ObjectInputStream & SnakeYAML on untrusted input
      var yamlConfig = req.getParameter("yaml")
      if (yamlConfig != null) {
        var yaml = new Yaml()
        var parsed = yaml.load(yamlConfig)
        resp.getWriter().println(parsed.toString())
      } else {
        var ois = new ObjectInputStream(req.getInputStream())
        var obj = ois.readObject()
        ois.close()
        resp.getWriter().println(obj.toString())
      }
    }
  }

  override function doGet(req : HttpServletRequest, resp : HttpServletResponse) {
    // 5. Path Traversal / Arbitrary File Read (CWE-22): Unsanitized path joined to base directory
    var docPath = req.getParameter("document")
    var file = new File("/var/claims/attachments/" + docPath)
    var fis = new FileInputStream(file)
    var content = Files.readAllBytes(Paths.get("/var/claims/attachments/" + docPath))
    fis.close()

    resp.setContentType("application/octet-stream")
    resp.getOutputStream().write(content)
  }
}
