from urllib.parse import quote
from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "your_secret_key"
bcrypt = Bcrypt(app)

# Пример базы данных пользователей
users = {
    "user1": {
        "username": "user1",
        "password": bcrypt.generate_password_hash("password1").decode("utf-8"),
        "email": "user1@example.com",
        "verified": False,
    }
}


# Форма создания нового пользователя
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        if username in users:
            return "Имя пользователя уже занято"

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        users[username] = {
            "username": username,
            "password": hashed_password,
            "email": email,
            "verified": False,
        }

        # Отправка ссылки для подтверждения регистрации на почту пользователя
        # Здесь должен быть код отправки почты с уникальной ссылкой
        verify_link = "http://localhost:5000/verify/{}".format(quote(username))
        print(verify_link)
        return "Регистрация успешно завершена. Проверьте вашу почту для подтверждения регистрации."

    return render_template("signup.html")


# Форма подтверждения регистрации
@app.route("/verify/<username>", methods=["GET"])
def verify(username):
    if username in users:
        users[username]["verified"] = True
        return "Регистрация подтверждена. Можете войти в систему."
    return "Недействительная ссылка для подтверждения регистрации."


# Форма входа пользователя
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if (
            username in users
            and bcrypt.check_password_hash(users[username]["password"], password)
            and users[username]["verified"] is True
        ):
            session["username"] = username
            return "Вход выполнен успешно."

        return "Неправильное имя пользователя или пароль."

    return render_template("login.html")


# Метод сброса пароля
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]

        if username in users and users[username]["email"] == email:
            # Генерация и отправка ссылки для сброса пароля на почту пользователя
            # Здесь должен быть код отправки почты с уникальной ссылкой для сброса пароля
            reset_link = "http://localhost:5000/update_password/{}".format(
                quote(username)
            )
            print(reset_link)

            return "Ссылка для сброса пароля отправлена на вашу почту."

        return "Неправильное имя пользователя или адрес электронной почты."

    return render_template("reset_password.html")


@app.route("/update_password/<username>", methods=["GET", "POST"])
def update_password(username):
    if request.method == "POST":
        password = request.form["password"]
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        users[username]["password"] = hashed_password
        return "Пароль успешно обновлен"
    return render_template("new_password.html", username=username)


# Безопасный выход из приложения
@app.route("/logout")
def logout():
    session.pop("username", None)
    return "Выход выполнен успешно."


if __name__ == "__main__":
    app.run(debug=True)
