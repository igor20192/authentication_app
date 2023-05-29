import http.server
import socketserver
import urllib.parse
import os
import hashlib
import base64
import ssl

PORT = 8000

users = {}


class RequestHandler(http.server.SimpleHTTPRequestHandler):
    """Custom request handler class for handling HTTP requests."""

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/":
            # Serve the registration.html page
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("registration.html", "rb") as file:
                self.wfile.write(file.read())
        elif self.path == "/login":
            # Serve the login.html page
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("login.html", "rb") as file:
                self.wfile.write(file.read())
        elif self.path == "/forgot_password":
            # Serve the forgot_password.html page
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("forgot_password.html", "rb") as file:
                self.wfile.write(file.read())

        elif self.path == "/logout":
            # Respond with a success message for logout
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("You have successfully logged out.".encode("utf-8"))

    def do_POST(self):
        """Handle POST requests."""
        if self.path == "/register":
            # Process registration form data
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode("utf-8")
            form_data = urllib.parse.parse_qs(post_data)

            username = form_data["username"][0]
            email = form_data["email"][0]
            password = form_data["password"][0]

            # Password complexity check
            if len(password) < 8:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    "The password must contain at least 8 characters.".encode("utf-8")
                )
                return

            if username in users:
                # User already exists
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("The user already exists.".encode("utf-8"))
                return

            if email in (users[username]["email"] for username in users):
                # User with the email already exists
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("User with this email already exists".encode("utf-8"))
                return
            # Hash the password
            salt = os.urandom(16)
            password_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt, 100000
            )

            # Save the user and their data
            users[username] = {
                "password_hash": password_hash,
                "salt": salt,
                "email": email,
            }

            response_message = "User successfully registered."
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(response_message.encode("utf-8"))

        elif self.path == "/forgot_password":
            # Process forgot password form data
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode("utf-8")
            form_data = urllib.parse.parse_qs(post_data)

            username = form_data["username"][0]

            if username not in users:
                # User not found
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("User is not found.".encode("utf-8"))
                return

            new_password = os.urandom(8).hex()

            # Hash the new password
            salt = os.urandom(16)
            password_hash = hashlib.pbkdf2_hmac(
                "sha256", new_password.encode(), salt, 100000
            )

            # Change the user's password
            users[username]["password_hash"] = password_hash
            users[username]["salt"] = salt

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(f"your new password: {new_password}".encode("utf-8"))

        elif self.path == "/login":
            # Process login form data
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode("utf-8")
            form_data = urllib.parse.parse_qs(post_data)

            username = form_data["username"][0]
            password = form_data["password"][0]

            if username not in users:
                # User not found
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("User is not found.".encode("utf-8"))
                return

            # Check password correctness
            stored_password_hash = users[username]["password_hash"]
            stored_salt = users[username]["salt"]
            password_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), stored_salt, 100000
            )

            if password_hash != stored_password_hash:
                # Incorrect password
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("Wrong password.".encode("utf-8"))
                return

            twofa_secret = base64.b32encode(os.urandom(10)).decode()
            users[username]["twofa_secret"] = twofa_secret
            print(twofa_secret)
            # Load the secret_key.html template
            with open("secret_key.html", "rb") as file:
                content = file.read().decode("utf-8")

            # Replace the placeholder {username} with the actual username value
            content = content.replace("{username}", username)

            # Send the modified template content as the response
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(content.encode("utf-8"))

        elif self.path == "/secret_key":
            # Process secret key form data
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode("utf-8")
            form_data = urllib.parse.parse_qs(post_data)

            secret = form_data["secret"][0]
            username = form_data["username"][0]
            if secret != users[username]["twofa_secret"]:
                # Incorrect 2FA code
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("Wrong 2FA code.".encode("utf-8"))
                return

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("Login completed successfully.".encode("utf-8"))

        elif self.path == "/logout":
            # Respond with a success message for logout
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                "You have successfully exited the program.".encode("utf-8")
            )


# Create an SSL/TLS context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
    httpd.socket = context.wrap_socket(httpd.socket)  # Apply SSL/TLS context
    print(f"Serving at port {PORT}")
    httpd.serve_forever()
