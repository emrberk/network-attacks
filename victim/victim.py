import http.server
import socketserver

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>Hello, Bystander!</h1></body></html>')
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b'<html><body><h1>Page Not Found</h1></body></html>')

# Set up the server
server_address = ('', 8000)
httpd = socketserver.TCPServer(server_address, MyHandler)

# Start the server and keep it running
print('Server listening on port 8000...')
httpd.serve_forever()

