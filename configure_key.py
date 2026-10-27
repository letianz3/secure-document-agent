"""Save a key locally with Windows current-user DPAPI. No plaintext file is written."""
import getpass
from secure_agent.credentials import KEY_PATH, load_key, save_key


def main():
    key = getpass.getpass("Google API key (hidden; saved encrypted for this Windows user): ").strip()
    save_key(key)
    if load_key() != key:
        raise SystemExit("Credential round-trip check failed")
    print("Encrypted local credential saved and verified. Excluded from submission ZIP.")
    print(f"Storage: {KEY_PATH}")


if __name__ == "__main__":
    main()
