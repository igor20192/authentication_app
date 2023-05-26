import unittest
from flask import Flask
from flask_testing import TestCase
from auth import app, db, User


class AppTestCase(TestCase):
    def create_app(self):
        app.config["TESTING"] = True
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        return app

    def setUp(self):
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_signup(self):
        response = self.client.post(
            "/signup",
            data={
                "username": "test_user",
                "email": "test@example.com",
                "password": "test_password",
            },
        )

        self.assertIn("Регистрация успешно завершена", response.data.decode())
        # Дополнительные проверки, например, проверка наличия созданного пользователя в базе данных
        user = User.query.filter_by(username="test_user").first()
        self.assertIsNotNone(user)
        self.assertFalse(user.verified)

    def test_login(self):
        # Создание пользователя
        user = User(
            username="test_user",
            email="test@example.com",
            password="test_password",
            verified=True,
        )
        db.session.add(user)
        db.session.commit()

        # Попытка входа с правильными учетными данными
        response = self.client.post(
            "/login",
            data={"username": "test_user", "password": "test_password"},
            follow_redirects=True,
        )
        self.assert200(response)
        self.assertIn("Вход выполнен успешно".encode("utf-8"), response.data)
        # Проверка, что имя пользователя сохранено в сессии
        with self.client.session_transaction() as session:
            self.assertEqual(session["username"], "test_user")

        # Попытка входа с неправильными учетными данными
        response = self.client.post(
            "/login",
            data={"username": "test_user", "password": "wrong_password"},
            follow_redirects=True,
        )
        self.assert200(response)
        self.assertIn(
            "Неправильное имя пользователя или пароль".encode("utf-8"), response.data
        )
        # Проверка, что имя пользователя не сохранено в сессии
        with self.client.session_transaction() as session:
            self.assertNotIn("username", session)

    def test_reset_password(self):
        # Создание пользователя
        user = User(
            username="test_user",
            email="test@example.com",
            password="test_password",
            verified=True,
        )
        db.session.add(user)
        db.session.commit()

        # Отправка запроса на сброс пароля
        response = self.client.post(
            "/reset_password",
            data={"username": "test_user", "email": "test@example.com"},
            follow_redirects=True,
        )
        self.assert200(response)
        self.assertIn(
            "Ссылка для сброса пароля отправлена на вашу почту".encode("utf-8"),
            response.data,
        )
        # Дополнительные проверки, например, проверка отправки электронной почты со ссылкой на сброс пароля

    def test_update_password(self):
        # Создание пользователя
        user = User(
            username="test_user",
            email="test@example.com",
            password="test_password",
            verified=True,
        )
