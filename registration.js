// registration.js
document.addEventListener("DOMContentLoaded", function () {
    // Обработчик формы регистрации
    var registrationForm = document.getElementById("registration-form");
    registrationForm.addEventListener("submit", function (event) {
        event.preventDefault();

        var formData = new FormData(registrationForm);

        // Отправка данных формы на сервер
        fetch("/register", {
            method: "POST",
            body: formData
        })
            .then(function (response) {
                return response.text();
            })
            .then(function (responseText) {
                // Обработка ответа сервера
                var responseDiv = document.getElementById("response-message");
                if (responseText.startsWith("User successfully registered.")) {
                    // Разбор ответа сервера и отображение 2FA ключа
                    var secretKey = responseText.split(":")[1].trim();
                    var twofaSecretDiv = document.getElementById("twofa-secret");
                    twofaSecretDiv.textContent = "Your 2FA secret key: " + secretKey;

                    responseDiv.textContent = responseText;
                    responseDiv.style.color = "green";
                } else {
                    responseDiv.textContent = responseText;
                    responseDiv.style.color = "red";
                }
            })
            .catch(function (error) {
                console.log(error);
            });
    });
});
