import unittest
import json
import os
from JWKS3 import app, conn, c, fernet, ph

class TestJWKSServer(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

        # Set the NOT_MY_KEY environment variable
        os.environ['NOT_MY_KEY'] = '_3qtOEdlbOTiYZnzn-3D9dAhmHed5fu4kNHj-wVlgXs='

    def tearDown(self):
        # Clean up test data
        c.execute("DELETE FROM users WHERE username = 'testuser'")
        conn.commit()

    def test_register_user(self):
        # Create a test user
        password = "password123"
        password_hash = ph.hash(password)
        c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", ("testuser", password_hash, "testuser@example.com"))
        conn.commit()

        # Test the register endpoint
        data = {"username": "newuser", "email": "newuser@example.com"}
        response = self.app.post("/register", data=json.dumps(data), content_type="application/json")
        self.assertEqual(response.status_code, 201)
        self.assertIn("password", json.loads(response.data))

        # Clean up the test user
        c.execute("DELETE FROM users WHERE username = 'testuser'")
        conn.commit()

    def test_authenticate_user(self):
        # Create a test user
        password = "password123"
        password_hash = ph.hash(password)
        c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", ("testuser", password_hash, "testuser@example.com"))
        conn.commit()

        # Test the authenticate endpoint
        data = {"username": "testuser", "password": "password123"}
        response = self.app.post("/auth", data=json.dumps(data), content_type="application/json")
        self.assertEqual(response.status_code, 200)
        self.assertIn("user_id", json.loads(response.data))

        # Clean up the test user
        c.execute("DELETE FROM users WHERE username = 'testuser'")
        conn.commit()

    def test_get_jwks(self):
        response = self.app.get("/jwks")
        self.assertEqual(response.status_code, 200)
        self.assertIn("keys", json.loads(response.data))

    def test_rate_limiter(self):
        # Create a test user
        password = "password123"
        password_hash = ph.hash(password)
        c.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", ("testuser", password_hash, "testuser@example.com"))
        conn.commit()

        data = {"username": "testuser", "password": "password123"}
        for _ in range(10):
            response = self.app.post("/auth", data=json.dumps(data), content_type="application/json")
            self.assertEqual(response.status_code, 200)

        # 11th request should be rate limited
        response = self.app.post("/auth", data=json.dumps(data), content_type="application/json")
        self.assertEqual(response.status_code, 429)
        self.assertIn("error", json.loads(response.data))

        # Clean up the test user
        c.execute("DELETE FROM users WHERE username = 'testuser'")
        conn.commit()

if __name__ == "__main__":
    unittest.main()
