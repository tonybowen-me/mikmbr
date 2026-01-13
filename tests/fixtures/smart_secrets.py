"""Test fixture for smart secret detection with various secret types."""

# Known pattern: AWS Access Key (should be detected with HIGH confidence)
aws_key = "AKIAIOSFODNN7EXAMPLE"

# Known pattern: GitHub Personal Access Token
github_token = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz1234"

# Known pattern: Slack Token
slack_webhook = "xoxb-1234567890-1234567890-abcdefghijklmnop"

# Known pattern: Stripe API Key
stripe_key = "sk_live_1234567890abcdefghijklmn"

# Known pattern: Google API Key
google_api = "AIzaSyAbcDefGhIjKlMnOpQrStUvWxYz12345"

# Known pattern: JWT
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# High entropy string (should be detected with MEDIUM confidence)
api_key = "aK9$mP2xQw7vBn5tYu3zRe8pLs4hGf1jDc6"

# Variable name + reasonable value (should be detected with MEDIUM confidence)
password = "my_secure_password_123"

# These should NOT be detected (placeholders)
placeholder_key = "your_api_key_here"
example_password = "changeme"
test_token = "12345"
dummy_secret = "example"

# These should NOT be detected (too short or obvious)
short_pwd = "abc123"
simple = "test"
