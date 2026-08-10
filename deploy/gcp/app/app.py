# The workload the sidecar fronts, and nothing else. It is deliberately a few
# lines: the point of Task 6 is that `parallax-attest` sits in front of an
# *unmodified* application, so anything here that acknowledged attestation
# would undercut the demonstration rather than support it.
#
# Binds loopback only, not 0.0.0.0. `docker-compose.yml` puts this container
# and the sidecar in one network namespace (`network_mode: "service:app"` on
# the `attest` service), so 127.0.0.1:3000 is exactly the surface the sidecar
# can reach — nothing else on the host, or on the confidential VM, can get to
# this process directly. The only route in is through the sidecar's RA-TLS
# listener.
from http.server import BaseHTTPRequestHandler, HTTPServer

# Changing this string changes the image's digest, which is what gets
# measured into RTMR3 (see `examples/gcp-c3.toml`). Task 7's "deploy a
# different image and watch the proxy refuse it" demonstration is this line.
BODY = b"hello from inside the trust domain\n"


class Fixed(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    # The default handler logs every request to stderr with a reverse DNS
    # lookup; silenced so the container's log is the sidecar's, not this.
    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 3000), Fixed).serve_forever()
