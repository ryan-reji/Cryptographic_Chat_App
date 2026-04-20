# CipherTalk: End-to-End Encrypted Chat

CipherTalk is a secure, real-time messaging application built with React and Firebase. It features a robust cryptographic stack using the Web Crypto API to ensure that messages remain private, even from the database provider.

## 🔐 Security Architecture

This application implements a multi-layer security protocol to ensure data integrity and confidentiality:

### 1. Key Exchange: ECDH (Elliptic Curve Diffie-Hellman)
Instead of sharing a password, the app uses **ECDH (P-256 curve)** to establish a shared secret.
* Each user generates a public/private key pair locally in the browser.
* The **Private Key never leaves your device.**
* The Public Key is shared via Firebase.
* Both users combine their own Private Key with the other's Public Key to arrive at the same **Shared Secret** independently.

### 2. Message Encryption: AES-256-GCM
All messages are encrypted before being sent to Firebase.
* **Algorithm:** AES (Advanced Encryption Standard) in GCM (Galois/Counter Mode).
* **Integrity:** GCM provides "authenticated encryption," meaning the app can detect if a message was tampered with.
* **IV (Initialization Vector):** Every message uses a unique, random IV so that the same message sent twice results in different ciphertext.

### 3. Identity & Auth: SHA-256 Salted Hashing
* Passwords are never stored in plaintext.
* The app uses **SHA-256** combined with a unique **16-byte salt** for each user to prevent rainbow table attacks.

## 🚀 Tech Stack
- **Frontend:** React.js (Vite)
- **Styling:** Tailwind CSS
- **Database:** Firebase Realtime Database
- **Cryptographic Engine:** Native Web Crypto API (SubtleCrypto)
- **Deployment:** Vercel

## 🛠️ Installation & Setup

1. **Clone the repository**
   ```bash
   git clone [https://github.com/your-username/ciphertalk.git](https://github.com/your-username/ciphertalk.git)
   cd ciphertalk

## Link: https://cryptographic-chat-app.vercel.app/
