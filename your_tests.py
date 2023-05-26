import unittest
from flask import session
from auth import app, db, User


class AppTestCase(unittest.TestCase):
    """Test case for the Flask application."""

    def setUp(self):
        """Set up the test environment."""
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        self.client = app.test_client()

        with app.app_context():
            db.create_all()

    def tearDown(self):
        """Tear down the test environment."""
        with app.app_context():
            db.drop_all()

    def test_signup(self):
        """Test the signup route."""

        response = self.client.post(
            "/signup",
            data={
                "username": "test_user",
                "email": "test@example.com",
                "password": "test123",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "Регистрация успешно завершена. Проверьте вашу почту для подтверждения регистрации.",
            response.data.decode(),
        )

    def test_verify(self):
        """Test the verify route."""
        user = User(username="test_user", email="test@example.com", password="test123")
        db.session.add(user)
        db.session.commit()

        response = self.client.get(f"/verify/{user.username}")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Registration confirmed", response.data.decode())

    def test_login(self):
        """Test the login route."""
        user = User(
            username="test_user",
            email="test@example.com",
            password="test123",
            verified=True,
        )
        db.session.add(user)
        db.session.commit()

        response = self.client.post(
            "/login", data={"username": "test_user", "password": "test123"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login successful", response.data.decode())
        self.assertIn("username", session)

    def test_reset_password(self):
        """Test the reset_password route."""
        user = User(
            username="test_user",
            email="test@example.com",
            password="test123",
            verified=True,
        )
        db.session.add(user)
        db.session.commit()

        response = self.client.post(
            "/reset_password",
            data={"username": "test_user", "email": "test@example.com"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Password reset link was sent", response.data.decode())

    def test_update_password(self):
        """Test the update_password route."""
        user = User(
            username="test_user",
            email="test@example.com",
            password="test123",
            verified=True,
        )
        db.session.add(user)
        db.session.commit()

        response = self.client.post(
            f"/update_password/{user.username}", data={"password": "newpassword"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Password successfully updated", response.data.decode())

    def test_logout(self):
        """Test the logout route."""
        with self.client.session_transaction() as sess:
            sess["username"] = "test_user"

        response = self.client.get("/logout")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Exit completed successfully", response.data.decode())
        self.assertNotIn("username", session)


if __name__ == "__main__":
    unittest.main()
