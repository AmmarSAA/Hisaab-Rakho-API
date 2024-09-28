# Hisaab Rakho API

Welcome to the Hisaab Rakho API. This API is designed to manage financial records and transactions efficiently.

## Table of Contents

- [Introduction](#introduction)
- [Getting Started](#getting-started)
- [Endpoints](#endpoints)
- [License](#license)

## Introduction

Hisaab Rakho API provides a set of endpoints to manage users, transactions, and financial records. It is built to be simple, secure, and scalable.

## Getting Started

To start using the Hisaab Rakho API, follow these steps:

1. **Clone the repository:**

    ```sh
    git clone https://github.com/ammarsaa/hisaab-rakho-api.git
    ```

2. **Install dependencies:**

    ```sh
    cd hisaab-rakho-api
    npm install -g json-server
    ```

3. **Run the server:**

    ```sh
    json-server --watch database.json --port 3000
    ```

## Endpoints

### User Endpoints

- **Create User**

    ```http
    POST /users
    ```

- **Get All Users**

    ```http
    GET /users
    ```

- **Get User By ID**

    ```http
    GET /users?id={id}
    ```

- **Get User By email**

    ```http
    GET /user?email={email}
    ```

### Transaction Endpoints

- **Create Transaction**

    ```http
    POST /transaction
    ```

- **Get All Transactions**

    ```http
    GET /transaction
    ```

- **Get Transaction By ID**

    ```http
    GET /transaction?id={id}
    ```

- **Get Transaction By User ID**

    ```http
    GET /transaction?user_id={user_id}
    ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
