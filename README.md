# Fuel Log Web App

This is a Node.js + Express web application for tracking vehicle fuel logs, user authentication, and basic fuel efficiency statistics. Data is stored locally using [NeDB](https://github.com/louischatriot/nedb).

## Features

- **User Registration & Login:** Secure authentication with hashed passwords.
- **Session Management:** User sessions via `express-session`.
- **Fuel Log CRUD:** Create, read, update, and delete fuel logs for each user.
- **Statistics:** Calculate fuel efficiency and cost per mile.
- **REST API:** Endpoints for managing fuel logs and retrieving stats.
- **Static Frontend:** HTML pages for registration, login, dashboard, and log management.

## Project Structure

```
index.js                # Main server file (Express app, API, DB setup)
db/
  users.db              # NeDB database for users
  fuel_logs.db          # NeDB database for fuel logs
public/
  index.html            # Home page
  register.html         # Registration page
  login.html            # Login page
  dashboard.html        # User dashboard
  new-log.html          # Add new fuel log
  edit-log.html         # Edit existing log
  stats.html            # Stats page
```

## How It Works

### 1. User Authentication

- **Registration:**  
  - POST `/register`  
  - Hashes password with bcrypt and stores user in NeDB.
  - Enforces unique usernames.

- **Login:**  
  - POST `/login`  
  - Checks credentials, creates session on success.

- **Session:**  
  - All protected routes require a valid session (`ensureAuth` middleware).

### 2. Fuel Log Management

- **List Logs:**  
  - GET `/api/fuel-logs`  
  - Returns all logs for the logged-in user.

- **Add Log:**  
  - POST `/api/fuel-logs`  
  - Adds a new fuel log (car name, amount, price, mileage, datetime).

- **Edit Log:**  
  - PUT `/api/fuel-logs/:id`  
  - Updates a log by ID (only if it belongs to the user).

- **Delete Log:**  
  - DELETE `/api/fuel-logs/:id`  
  - Deletes a log by ID (only if it belongs to the user).

### 3. Statistics

- **GET `/api/stats`**  
  - Calculates fuel efficiency (distance / total fuel) and cost per mile for the user’s logs.

### 4. Static Pages

- Served from the `public/` directory for registration, login, dashboard, log editing, and stats.

## Running the App

1. Install dependencies:
    ```sh
    npm install
    ```
2. Start the server:
    ```sh
    node index.js
    ```
3. Visit [http://localhost:3000](http://localhost:3000) in your browser.

## Dependencies

- express
- express-session
- bcrypt
- nedb
- path, fs (Node.js built-ins)

## Security Notes

- Passwords are hashed with bcrypt.
- All fuel log operations are scoped to the logged-in user.
- Sessions are required for all sensitive routes.

---
