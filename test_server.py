#!/usr/bin/env python3
"""
Vulnerable XPath test server for XPathMap testing.
DO NOT use in production — intentionally vulnerable!
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import xml.etree.ElementTree as ET

# In-memory XML "database"
XML_DATA = """<?xml version="1.0"?>
<store>
  <users>
    <user id="1">
      <username>admin</username>
      <password>s3cr3t!</password>
      <email>admin@example.com</email>
      <role>administrator</role>
    </user>
    <user id="2">
      <username>alice</username>
      <password>alice123</password>
      <email>alice@example.com</email>
      <role>user</role>
    </user>
    <user id="3">
      <username>bob</username>
      <password>b0bpass</password>
      <email>bob@example.com</email>
      <role>user</role>
    </user>
  </users>
  <products>
    <product id="101">
      <name>Laptop</name>
      <price>999.99</price>
      <stock>15</stock>
    </product>
    <product id="102">
      <name>Phone</name>
      <price>499.00</price>
      <stock>42</stock>
    </product>
  </products>
</store>
"""

def xpath_search(query_value):
    """Vulnerable XPath query — directly embeds user input."""
    try:
        import lxml.etree as etree
        root = etree.fromstring(XML_DATA.encode())
        # VULNERABLE: user input injected directly into XPath
        xpath = f"//user[username/text()='{query_value}']"
        results = root.xpath(xpath)
        if results:
            return "\n".join(
                ET.tostring(ET.fromstring(etree.tostring(r).decode()),
                            encoding='unicode')
                for r in results
            )
        return ""
    except Exception as e:
        return f"XPathException: {e}"


def xpath_search_plain(query_value):
    """Plain stdlib — uses ElementTree which has limited XPath."""
    try:
        root = ET.fromstring(XML_DATA)
        # Intentionally vulnerable
        results = root.findall(f".//user[username='{query_value}']")
        if results:
            return "\n".join(ET.tostring(r, encoding='unicode') for r in results)
        return "No results"
    except ET.ParseError as e:
        return f"XPath error: {e}"
    except Exception as e:
        return f"Error: {e}"


class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  [REQ] {self.address_string()} - {fmt % args}")

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        name   = params.get("name", [""])[0]

        # Try lxml first; fall back to stdlib
        try:
            import lxml.etree as etree
            result = xpath_search(name)
        except ImportError:
            result = xpath_search_plain(name)

        body = f"""<html><body>
<h2>XPath Search</h2>
<form method="GET"><input name="name" value="{name}"><button>Search</button></form>
<pre>{result if result else 'No results found.'}</pre>
</body></html>"""

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


if __name__ == "__main__":
    import socketserver
    port = 7171
    # Allow address reuse
    HTTPServer.allow_reuse_address = True
    server = HTTPServer(("127.0.0.1", port), VulnHandler)
    print(f"[*] Vulnerable XPath test server listening on http://127.0.0.1:{port}")
    print(f"[*] Test URL: http://127.0.0.1:{port}/search?name=admin")
    print(f"[*] Ctrl+C to stop\n")
    server.serve_forever()
