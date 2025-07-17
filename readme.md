# cyberdudebivash's Advanced Password Manager with Biometrics

## Description

This is a secure password manager application with biometric authentication (face recognition), advanced cryptography, and latest features like AI password strength analysis, dark web breach checks, 2FA support, and secure vault storage.

**Note:** For educational purposes. Requires camera for biometrics. Install dependencies and run on a secure system. Biometrics are basic—use for testing only.

## Requirements

- Python 3.x
- Camera for biometrics
- Packages: See `requirements.txt` (note: face_recognition requires dlib; install via pip if needed)

## Installation

1. Install dependencies: `pip install -r requirements.txt`
2. Run `python main.py`

## Usage

1. Launch: `python main.py`
2. Setup biometrics first (captures face).
3. Login with master password or biometrics.
4. Add entries, generate strong passwords (with strength check via zxcvbn).
5. View vault (decrypted on-the-fly).
6. Check email breaches via HaveIBeenPwned API.
7. Setup/verify 2FA with QR code.

## Features (Latest 2025 Trends)

- **Cryptography**: Argon2 for master key derivation, Fernet (AES-256) for encryption.
- **Biometrics**: Face recognition for auth.
- **Password Gen**: Secure random with entropy checks.
- **Strength Analysis**: AI-based via zxcvbn.
- **Breach Monitoring**: Dark web checks.
- **2FA**: TOTP support with QR.
- **Zero-Knowledge**: All encryption client-side.

## Limitations

- Biometrics: Basic; not production-grade (e.g., no liveness detection).
- Storage: Encrypted SQLite; backup DB securely.
- No autofill (simulate via copy-paste).
- Expand with post-quantum crypto (e.g., Kyber) if needed.

## License

MIT License .

##COPYRIGHT@CYBERDUDEBIVASH  2025