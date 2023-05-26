from flask_sqlalchemy import SQLAlchemy
from urllib.parse import quote
from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt
from flask_talisman import Talisman


app = Flask(__name__)
app.secret_key = "your_secret_key"
bcrypt = Bcrypt(app)
talisman = Talisman(app)


# Database settings
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    """User model

    Attributes:
        id (int): The unique identifier of the user.
        username (str): User name. A unique mandatory field.
        password (str): The user's hashed password. Obligatory field.
        email (str): The user's email address. A unique field that must be filled in.
        verified (bool): Flag indicating whether the user's registration is verified.

    Methods:
        __repr__(): Returns a string representation of the user model."""

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    verified = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<User {self.username}>"


@app.before_request
def create_tables():
    """Creates tables in the database before each query.

    This decorator function performs the creation of database tables
    before each request to the Flask application."""
    db.create_all()


@app.route("/signup", methods=["GET", "POST"])
@talisman(force_https=True, content_security_policy=None)
def signup():
    """Processes the form for creating a new user.

    If POST request method, creates a new user based on
    form data and stores it in the database.
    If registration is successful, sends a registration confirmation email.
    If request method GET, displays page with registration form.

    Returns:
        If POST request method:
            - "Registration completed successfully. Check your email to confirm registration."
        If GET request method:
            - Registration form page."""
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return "Имя пользователя уже занято"

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(
            username=username, password=hashed_password, email=email, verified=False
        )
        db.session.add(new_user)
        db.session.commit()

        verify_link = "http://localhost:5000/verify/{}".format(quote(username))
        print(verify_link)
        return "Регистрация успешно завершена. Проверьте вашу почту для подтверждения регистрации."

    return render_template("signup.html")


@app.route("/verify/<username>", methods=["GET"])
@talisman(force_https=True, content_security_policy=None)
def verify(username):
    """Processes confirmation of user registration.

    Checks if there is a user with the specified user name.
    If the user is found, sets the verified flag to True and saves the changes.
    Returns a registration verification message or an invalid link.

    Arguments:
        username (str): The username to verify the registration.

    Returns:
        If the user is found:
            - "Registration confirmed. You may log in."
        If the user is not found:
            - "Invalid registration confirmation link."
    """
    user = User.query.filter_by(username=username).first()

    if user:
        user.verified = True
        db.session.commit()
        return "Регистрация подтверждена. Можете войти в систему."

    return "Недействительная ссылка для подтверждения регистрации."


@app.route("/login", methods=["GET", "POST"])
@talisman(force_https=True, content_security_policy=None)
def login():
    """Processes the user login form.

    If the request method is POST, it checks the form data sent
    and performs the user login if the data is correct.
    If the request method is GET, displays the page with the login form.

    Returns:
        If POST request method:
            - "Login successful."
        If GET request method:
            - The page with the login form.

    """
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if (
            user
            and bcrypt.check_password_hash(user.password, password)
            and user.verified is True
        ):
            session["username"] = user.username
            return "Вход выполнен успешно."

        return "Неправильное имя пользователя или пароль."

    return render_template("login.html")


@app.route("/reset_password", methods=["GET", "POST"])
@talisman(force_https=True, content_security_policy=None)
def reset_password():
    """Processes the password reset form.

    If request method is POST, it checks sent form data
    and sends an email with a link to reset the password if the data is correct.
    If GET request method, displays page with password reset form.

    Returns:
        If POST request method:
            - "The password reset link was sent to your email."
        If GET request method:
            - The page with the password reset form.
    """
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]

        user = User.query.filter_by(username=username).first()
        if user and user.email == email:
            reset_link = "http://localhost:5000/update_password/{}".format(
                quote(username)
            )
            print(reset_link)

            return "Ссылка для сброса пароля отправлена на вашу почту."

        return "Неправильное имя пользователя или адрес электронной почты."

    return render_template("reset_password.html")


@app.route("/update_password/<username>", methods=["GET", "POST"])
@talisman(force_https=True, content_security_policy=None)
def update_password(username):
    """Processes the form to update the user's password.

    If POST request method, updates user password based on
    sent a new password and saves the changes to the database.
    If GET request method, displays the page with the form for entering the new password.

    Arguments:
        username (str): The name of the user for whom the password is being updated.

    Returns:
        If POST request method:
            - "Password successfully updated."
        If GET request method:
            - The page with the new password entry form.
    """
    if request.method == "POST":
        password = request.form["password"]
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        user = User.query.filter_by(username=username).first()
        if user:
            user.password = hashed_password
            db.session.commit()
        return "Пароль успешно обновлен"
    return render_template("new_password.html", username=username)


@app.route("/logout")
@talisman(force_https=True, content_security_policy=None)
def logout():
    """Executes a safe exit from the application.

    Deletes the username from the session.

    Returns:
        - "Exit completed successfully."
    """
    session.pop("username", None)
    return "Выход выполнен успешно."


if __name__ == "__main__":
    app.run(debug=True)
