import unittest
import urllib.request
from bs4 import BeautifulSoup


class TestServer(unittest.TestCase):
    """
    Unit tests for server functionality.
    """

    def test_registration(self):
        """
        Test user registration functionality.
        """
        # Create a POST request with registration form data
        url = "http://localhost:8000/register"
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "testpassword",
        }
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")

        # Send the request to the server
        request = urllib.request.Request(url, encoded_data, headers=headers)
        response = urllib.request.urlopen(request)

        # Check the response
        self.assertEqual(response.code, 200)
        self.assertEqual(
            response.read().decode("utf-8"), "User successfully registered."
        )

        # Attempt to register the same user again
        request1 = urllib.request.Request(url, encoded_data, headers=headers)
        response1 = urllib.request.urlopen(request1)
        self.assertEqual(response1.code, 200)
        self.assertEqual(response1.read().decode("utf-8"), "The user already exists.")

    def test_login(self):
        """
        Test user login functionality.
        """
        # Create a POST request with login form data
        url = "http://localhost:8000/login"
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {"username": "testuser", "password": "testpassword"}
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")

        # Send the request to the server
        request = urllib.request.Request(url, encoded_data, headers=headers)
        response = urllib.request.urlopen(request)

        # Check the response
        self.assertEqual(response.code, 200)

        # Load expected output from file
        with open("secret_key.html", "r") as file:
            expected_output = file.read()

        # Parse HTML code using BeautifulSoup
        soup_template = BeautifulSoup(response.read().decode("utf-8"), "html.parser")
        soup_expected = BeautifulSoup(expected_output, "html.parser")

        self.maxDiff = None

        # Compare the generated HTML code with the expected result
        self.assertEqual(
            str(soup_template),
            str(soup_expected).replace("{username}", data["username"]),
        )

        # Test login with invalid user
        data1 = {"username": "testuser1", "password": "testpassword"}
        encoded_data1 = urllib.parse.urlencode(data1).encode("utf-8")
        request1 = urllib.request.Request(url, encoded_data1, headers=headers)
        response1 = urllib.request.urlopen(request1)
        self.assertEqual(response1.read().decode("utf-8"), "User is not found.")

    def test_forgot_password(self):
        """
        Test forgot password functionality.
        """
        # Create a POST request with forgot password form data
        url = "http://localhost:8000/forgot_password"
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        data = {"username": "testuser"}
        encoded_data = urllib.parse.urlencode(data).encode("utf-8")

        # Send the request to the server
        request = urllib.request.Request(url, encoded_data, headers=headers)
        response = urllib.request.urlopen(request)

        # Check the response
        self.assertEqual(response.code, 200)
        self.assertRegex(response.read().decode("utf-8"), "your new password:")

    def test_logout(self):
        """
        Test user logout functionality.
        """
        # Create a GET request for logout
        url = "http://localhost:8000/logout"

        # Send the request to the server
        response = urllib.request.urlopen(url)

        # Check the response
        self.assertEqual(response.code, 200)
        self.assertEqual(
            response.read().decode("utf-8"), "You have successfully logged out."
        )


if __name__ == "__main__":
    unittest.main()
