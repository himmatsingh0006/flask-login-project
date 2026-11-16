import sqlite3
import os
import tempfile
import unittest
from contextlib import closing

from app import create_app
from werkzeug.security import check_password_hash


class LoginAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database = os.path.join(self.temp_dir.name, "test.db")
        self.app = create_app(
            {
                "TESTING": True,
                "SECRET_KEY": "test-key",
                "DATABASE": self.database,
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def csrf_token(self):
        response = self.client.get("/?mode=signup")
        marker = b'name="csrf_token" value="'
        return response.data.split(marker, 1)[1].split(b'"', 1)[0].decode()

    def test_registration_saves_a_hashed_password_and_login_works(self):
        token = self.csrf_token()
        response = self.client.post(
            "/register",
            data={
                "csrf_token": token,
                "name": "Alex Morgan",
                "email": "ALEX@example.com",
                "password": "correct-horse",
                "password_confirmation": "correct-horse",
            },
        )
        self.assertEqual(response.status_code, 302)

        with closing(sqlite3.connect(self.database)) as connection:
            connection.row_factory = sqlite3.Row
            user = connection.execute(
                "SELECT name, email, password_hash FROM users"
            ).fetchone()

        self.assertEqual(user["name"], "Alex Morgan")
        self.assertEqual(user["email"], "alex@example.com")
        self.assertNotEqual(user["password_hash"], "correct-horse")
        self.assertTrue(check_password_hash(user["password_hash"], "correct-horse"))

        token = self.csrf_token()
        response = self.client.post(
            "/login",
            data={
                "csrf_token": token,
                "email": "alex@example.com",
                "password": "correct-horse",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/dashboard")
        self.assertIn(b"Welcome, Alex Morgan.", self.client.get("/dashboard").data)

    def test_rejects_mismatched_passwords_and_missing_csrf_token(self):
        response = self.client.post(
            "/register",
            data={
                "csrf_token": self.csrf_token(),
                "name": "Alex",
                "email": "alex@example.com",
                "password": "correct-horse",
                "password_confirmation": "different-password",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"Your passwords do not match.", response.data)

        response = self.client.post(
            "/register",
            data={
                "name": "Alex",
                "email": "alex@example.com",
                "password": "correct-horse",
                "password_confirmation": "correct-horse",
            },
        )
        self.assertEqual(response.status_code, 400)

if __name__ == "__main__":
    unittest.main()
