# Test scenarios

Import files under `fixtures/linux/` to exercise detections:

| Fixture | Expected detections |
|---------|---------------------|
| `auth_bruteforce.log` | SSH Brute Force |
| `password_spray.log` | Password Spraying |
| `auth_success_after_fail.log` | Successful Login After Failures |
| `sudo_activity.log` | Linux Sudo Activity |
| `baseline.log` | None (negative control) |

Windows `.evtx` files are not shipped as binary fixtures. Use real exported logs locally or run parser unit tests with embedded XML samples.
