# Simple Authentication Server

This is a simple authentication server written in Python using the `http.server` and `socketserver` modules. It provides basic registration, login, and password recovery functionality.

## Features

- Registration: Users can register by providing a unique username, email, and password.
- Login: Registered users can log in using their username and password.
- Password Recovery: Users can request a password reset by providing their username. A new password will be generated and sent to them.
- Two-Factor Authentication: After successful login, users are required to enter a two-factor authentication (2FA) code generated by an authenticator app.

## Prerequisites

- Python 3.x
- `http.server` module (built-in)
- `socketserver` module (built-in)
- `urllib.parse` module (built-in)
- `os` module (built-in)
- `hashlib` module (built-in)
- `base64` module (built-in)
- `ssl` module (built-in)

## Usage

1. Clone the repository or download the code files.

   ```shell
   git clone https://github.com/igor20192/authentication_app.git

2. Generate SSL/TLS certificates (`server.crt` and `server.key`) for secure communication (optional but recommended).
3. Open a terminal or command prompt and navigate to the project directory.
4. Run the following command to start the authentication server:

   ```shell
   python auth_user.py
