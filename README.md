# Basic Flask Server Project 🚀

This project is a basic Flask web server with user authentication, file management, network scanning, and a Monty Hall game. It uses MySQL for the database and includes features like user login, registration, admin access control, file uploading, and device scanning on the network.

## Project Structure 📂

The project is structured as follows:

*   `main.py`: The main application file that defines the Flask routes and application logic. 🚦
*   `app_config.py`: Contains the Flask application configuration settings, such as database URI and secret key. ⚙️
*   `host_settings.py`: Loads the host and port configuration from `host_settings.json`. 🌐
*   `host_settings.json`: JSON file containing the host and port settings for the Flask application. 🔧
*   `tables.py`: Defines the database models using Flask-SQLAlchemy. 🗄️
*   `login_required.py`: Defines a decorator to protect routes that require user login. 🔑
*   `admin_required.py`: Defines a decorator to protect routes that require admin access. 🛡️
*   `passcontrol.py`: Contains a function to validate password strength. 🔒
*   `device_scanner.py`: Contains the `NetworkScanner` class for scanning devices on the network. 📡
*   `log_class.py`: Defines the `UserInfo` class for collecting and logging user information. 📝
*   `log_config.py`: Configures the logging system for the application. 🗂️
*   `requirements.txt`: Lists the Python packages required to run the application. 📚
*   `templates/`: Contains the HTML templates for the web pages. 🖼️
*   `uploads/`: Directory where uploaded files are stored. 📤

## File Descriptions 📝

*   **`main.py`**: This is the main application file. It handles routing, user authentication, file uploads, and network scanning. It imports and uses the configurations, database models, and utility functions defined in other files. 🚦

*   **`app_config.py`**: This file configures the Flask application. It sets the database URI, disables modification tracking, sets the secret key, and defines the upload folder. ⚙️

*   **`host_settings.py`**: This file reads the host and port settings from `host_settings.json` and makes them available to the application. 🌐

*   **`host_settings.json`**: This JSON file contains the host and port settings for the Flask application. It allows you to easily change the host and port without modifying the code. 🔧

    ```json
    {
        "host": "0.0.0.0",
        "port": "8883"
    }
    ```

*   **`tables.py`**: This file defines the database models using Flask-SQLAlchemy. It includes models for `Users`, `Uploads`, `MacAdrs`, and `MontyHallGames`. 🗄️

*   **`login_required.py`**: This file defines a decorator that protects routes that require user login. If a user is not logged in, they are redirected to the login page. 🔑

*   **`admin_required.py`**: This file defines a decorator that protects routes that require admin access. If a user is not an admin, they are redirected to the 404 page. 🛡️

*   **`passcontrol.py`**: This file contains a function, `is_password_valid`, that checks if a password meets certain criteria (minimum length, uppercase, lowercase, digit, and special character). 🔒

*   **`device_scanner.py`**: This file contains the `NetworkScanner` class, which is responsible for scanning devices on the network. It uses `ping` and port scanning to identify devices and determine their operating systems. 📡

*   **`log_class.py`**: This file defines the `UserInfo` class, which collects user information such as username, IP address, login time, and device type. It also logs this information using the logging system. 📝

*   **`log_config.py`**: This file configures the logging system for the application. It sets up different loggers for different levels of messages (info, error, critical) and configures them to write to different files and the console. 🗂️

*   **`requirements.txt`**: This file lists all the Python packages that are required to run the application. It is used by `pip` to install the dependencies. 📚

## How to Use `requirements.txt` ⚙️

The `requirements.txt` file is used to manage the project's dependencies. To install all the required packages, run the following command in the project directory:

```bash
pip install -r requirements.txt
```

This command will install all the packages listed in the `requirements.txt` file, along with their dependencies.

## Installation 🛠️

1.  Clone the repository:

    ```bash
    git clone [repository_url]
    cd basicFlaskServer
    ```

2.  Create a virtual environment (recommended):

    ```bash
    python -m venv venv
    venv\Scripts\activate   # On Windows 💻
    source venv/bin/activate  # On Linux/macOS 🐧🍎
    ```

3.  Install the dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4.  Configure the database:

    *   Ensure you have MySQL and XAMPP installed and running. 💽
    *   Create a database named `M883LFS`.
    *   Update the database URI in `app_config.py` with your MySQL credentials.

5.  Run the application:

    ```bash
    python main.py
    ```

## Configuration ⚙️

*   **Database:** Configure the database connection in `app_config.py`. 🗄️
*   **Host and Port:** Configure the host and port in `host_settings.json`. 🌐
*   **Secret Key:** Change the secret key in `app_config.py` for security. 🔑

## Usage 🧭

1.  **Access the application:** Open a web browser and navigate to the host and port specified in `host_settings.json` (e.g., `http://localhost:8883`). 🌐
2.  **User Registration:** Register a new user account. 📝
3.  **Login:** Log in with your registered account. 🔑
4.  **Admin Access:** The first registered user is automatically assigned admin rights. 🛡️
5.  **File Upload:** Upload files via the upload page. 📤
6.  **Network Scanning:** Scan your local network for devices via the server settings page (admin access required). 📡
7.  **Monty Hall Game:** Play the Monty Hall game. 🎲

## Security Notes ⚠️

*   **Secret Key:** Ensure the `SECRET_KEY` in `app_config.py` is a strong, randomly generated string. 🔑
*   **Password Validation:** The `is_password_valid` function in `passcontrol.py` enforces password complexity rules. 🔒
*   **Admin Access:** The `admin_required` decorator protects sensitive routes. 🛡️
*   **MAC Address Blocking:** The application includes functionality to block devices by MAC address. 🚫

## Contributing 🤝

Feel free to contribute to this project by submitting pull requests. 🎁