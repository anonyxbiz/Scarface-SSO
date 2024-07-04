# Scarface SSO Web App

Scarface SSO (Single Sign-On) Web App is a web app designed for user authentication and session management. This app leverages asynchronous programming and integrates with external services for secure authentication and authorization.

## Features

- **Authentication**: Secure user login and registration with password complexity checks.
- **Session Management**: Persistent user sessions using encrypted cookies.
- **Two-Step Verification**: Email-based verification for added security during login.
- **Middleware**: Custom middleware for protecting routes and filtering requests based on IP and user-agent.
- **NoSQL Database**: Utilizes a custom NoSQL framework for efficient data storage and retrieval.
- **Asynchronous Operations**: Utilizes asyncio for concurrent task handling, ensuring smooth performance.

## Requirements

- Python 3.7+
- Dependencies listed in `requirements.txt`
- Environment variables:
  - `safe_key`: Fernet key
  - `mailjet_api_key`: API key for Mailjet integration.
  - `mailjet_secret_key`: Secret key for Mailjet integration.
  - `mailjet_mail`: Mailjet sender email.
  - `mailjet_name`: Mailjet sender name.
  - `app_url`: Base URL of the application.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/anonyxbiz/Scarface-SSO.git
   cd Scarface-SSO
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```
   export mailjet_api_key='your_mailjet_api_key'
   export mailjet_secret_key='your_mailjet_secret_key'
   export app_url='https://yourappurl.com'
   ```

## Usage

1. Run the application:
   ```
   python app.py
   ```

2. Access the application in your browser at `http://localhost:8001`.

## Configuration

- Update `middleware.allowed_hosts` in `app.py` to include your deployment hosts.
- Customize email templates and verification URLs in `Verification.two_step_verification`.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Note from the Developer

It was fun making this project and it was solely meant for fun.
