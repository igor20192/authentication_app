import http.server
import socketserver
import urllib.parse
import os
import hashlib
from otpauth import TOTP
import base64
import ssl

PORT = 8000

users = {}


class RequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("registration.html", "rb") as file:
                self.wfile.write(file.read())
        elif self.path == "/login":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("login.html", "rb") as file:
                self.wfile.write(file.read())
        elif self.path == "/forgot_password":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            with open("forgot_password.html", "rb") as file:
                self.wfile.write(file.read())
        elif self.path == "/logout":
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write("You have successfully logged out.".encode("utf-8"))

    def do_POST(self):
        if self.path == "/register":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode("utf-8")
            form_data = urllib.parse.parse_qs(post_data)

            username = form_data["username"][0]
            email = form_data["email"][0]
            password = form_data["password"][0]
            twofa_secret = base64.b32encode(os.urandom(10)).decode()

            # Проверка сложности пароля
            if len(password) < 8:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    "The password must contain at least 8 characters.".encode("utf-8")
                )
                return

            if username in users:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("The user already exists.".encode("utf-8"))
                return

            # Хэширование пароля
            salt = os.urandom(16)
            password_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt, 100000
            )

            # Сохранение пользователя и его данных
            users[username] = {
                "password_hash": password_hash,
                "salt": salt,
                "twofa_secret": twofa_secret,
            }

            tw_secret = users[username]["twofa_secret"]
            response_message = (
                f"User successfully registered. Your 2FA secret: {tw_secret}"
            )
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            # Отправка 2FA ключа на страницу

            self.wfile.write(response_message.encode("utf-8"))

        elif self.path == "/forgot_password":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode("utf-8")
            form_data = urllib.parse.parse_qs(post_data)

            username = form_data["username"][0]

            if username not in users:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("User is not found.".encode("utf-8"))
                return

            new_password = os.urandom(8).hex()

            # Хэширование нового пароля
            salt = os.urandom(16)
            password_hash = hashlib.pbkdf2_hmac(
                "sha256", new_password.encode(), salt, 100000
            )

            # Изменение пароля пользователя
            users[username]["password_hash"] = password_hash
            users[username]["salt"] = salt

            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(f"your new password: {new_password}".encode("utf-8"))

        elif self.path == "/login":
            content_length = int(self.headers["Content-Length"])
            post_data = self.rfile.read(content_length).decode("utf-8")
            form_data = urllib.parse.parse_qs(post_data)

            username = form_data["username"][0]
            password = form_data["password"][0]
            twofa_code = form_data["twofa_code"][0]

            if username not in users:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("User is not found.".encode("utf-8"))
                return

            # Проверка правильности пароля
            stored_password_hash = users[username]["password_hash"]
            stored_salt = users[username]["salt"]
            password_hash = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), stored_salt, 100000
            )

            if password_hash != stored_password_hash:
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write("Wrong password.".encode("utf-8"))
                return

            # Проверка правильности 2FA-кода
            stored_twofa_secret = users[username]["twofa_secret"]
            # totp = TOTP(stored_twofa_secret)
            # if not totp.verify(twofa_code):
            if stored_twofa_secret != twofa_code:
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
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                "You have successfully exited the program.".encode("utf-8")
            )


# Создание контекста SSL/TLS
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

with socketserver.TCPServer(("", PORT), RequestHandler) as httpd:
    httpd.socket = context.wrap_socket(httpd.socket)  # Применение контекста SSL/TLS
    print(f"Serving at port {PORT}")
    httpd.serve_forever()
