# Northstar login app

A polished sign-in and account-creation page built with Python, Flask, and SQLite. New accounts are saved in `instance/users.db`; passwords are stored as secure hashes, never as plain text.

## Run locally

1. Install Python 3.10 or newer.
2. In this folder, install the app dependency:

   ```powershell
   python -m pip install -r requirements.txt
   ```

3. Start the server:

   ```powershell
   python app.py
   ```

4. Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser and choose **Create account**.

The database and its `users` table are created automatically the first time the app starts. For a deployment, set a private, persistent `SECRET_KEY` environment variable and serve the app over HTTPS.
