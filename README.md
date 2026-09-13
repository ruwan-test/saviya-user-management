# saviya-user-management

This is a sample REST API for user management in **Saviya**.

The API uses **JWT token based authentication**. After sign-in, the client receives a short-lived access token (JWT) and a refresh token. Send the access token as `Authorization: Bearer <accessToken>` on protected requests. When the access token expires, exchange the refresh token at `POST /manage-users/refresh` for a new pair.

## User types

There are **2 user types**:

| Role | Description |
| --- | --- |
| `ROLE_ADMIN` | Full access. Can look up and delete other users. |
| `ROLE_CLIENT` | Standard user. Can sign in and read their own profile (`GET /manage-users/me`). Cannot look up or delete other accounts. |

## How to test

Use **Docker Compose**. That starts the Spring application and MySQL together.

```bash
docker compose up --build
```

Wait until both containers are healthy. The API is then available at:

- Application: http://localhost:8080
- Swagger UI: http://localhost:8080/swagger-ui.html

On startup the `dev` profile creates **2 sample users**:

| Username | Password | Role |
| --- | --- | --- |
| `admin` | `admin@abc` | `ROLE_ADMIN` |
| `john` | `john@123` | `ROLE_CLIENT` |

### Sign in as admin

```bash
curl -X POST "http://localhost:8080/manage-users/signin?username=admin&password=admin@abc"
```

Use the `accessToken` from the response:

```bash
curl -H "Authorization: Bearer <accessToken>" http://localhost:8080/manage-users/me
```

### Sign in as client

```bash
curl -X POST "http://localhost:8080/manage-users/signin?username=john&password=john@123"
```

### Stop

```bash
docker compose down
```

Add `-v` if you also want to remove the MySQL data volume.

## API endpoints

Base path: `/manage-users`

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| `POST` | `/signin` | No | Sign in. Returns access and refresh tokens. |
| `POST` | `/signup` | No | Register a new user. No tokens are issued. |
| `GET` | `/me` | Admin or client | Current authenticated user. |
| `GET` | `/{username}` | Admin | Look up a user by username. |
| `DELETE` | `/{username}` | Admin | Delete a user. |
| `POST` | `/refresh` | Refresh token in body | Issue a new token pair. |
| `POST` | `/logout` | Refresh token in body | Revoke the refresh token. |
