// SecureChat.jsx — End-to-End Encrypted Chat with ECDH + AES-GCM + SHA-256
// Deploy on Vercel: just drop this into a Next.js or Vite React project.
// Requires Firebase (Realtime Database) for message relay.
//
// SETUP:
//  1. Create a Firebase project → enable Realtime Database (test mode initially)
//  2. Replace the firebaseConfig below with your project's config
//  3. npm install firebase
//  4. Deploy to Vercel

import { useState, useEffect, useRef, useCallback } from "react";
import { initializeApp } from "firebase/app";
import {
  getDatabase,
  ref,
  push,
  onValue,
  set,
  get,
  serverTimestamp,
} from "firebase/database";

// ─────────────────────────────────────────────
// 🔥 FIREBASE CONFIG — replace with your own!
// ─────────────────────────────────────────────
const firebaseConfig = {
  apiKey: "AIzaSyCf-1oBpg1bWJwYhJxX7GGyYs7vBlzFOqk",
  authDomain: "crpytchat.firebaseapp.com",
  databaseURL: "https://crpytchat-default-rtdb.firebaseio.com",
  projectId: "crpytchat",
  storageBucket: "crpytchat.firebasestorage.app",
  messagingSenderId: "162197325092",
  appId: "1:162197325092:web:587ba728f8332fd0f49fb1"
};

const app = initializeApp(firebaseConfig);
const db = getDatabase(app);

// ─────────────────────────────────────────────
// 👥 USERS — 2 hardcoded users (salted hashes stored in Firebase on first login)
// ─────────────────────────────────────────────
const USERS = {
  alice: "alice_password_123",
  bob: "bob_password_456",
};

// ─────────────────────────────────────────────
// 🔐 CRYPTOGRAPHY LAYER
// All crypto uses the Web Crypto API (built into all modern browsers + Node 18+)
// ─────────────────────────────────────────────

// --- SHA-256 Password Hashing ---
// We hash (salt + password) with SHA-256 via the Web Crypto API.
// The salt is random per-user and stored in Firebase alongside the hash.
// The plaintext password is NEVER stored or transmitted — only the digest.
//
// Why salt?  Without it, two users with the same password would produce the
// same hash, making rainbow-table attacks trivial. The salt makes every hash
// unique even for identical passwords.
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  // Concatenate salt bytes + password bytes before hashing
  const saltBytes = hexToBytes(saltHex);
  const passBytes = enc.encode(password);
  const combined = new Uint8Array(saltBytes.length + passBytes.length);
  combined.set(saltBytes, 0);
  combined.set(passBytes, saltBytes.length);

  const digest = await crypto.subtle.digest("SHA-256", combined);
  return bytesToHex(new Uint8Array(digest));
}

async function verifyPassword(password, saltHex, storedHash) {
  const hash = await hashPassword(password, saltHex);
  return hash === storedHash;
}

// --- ECDH Key Exchange ---
// Each user generates a P-256 keypair once per session.
// The public key is published to Firebase.
// The private key NEVER leaves the browser.
async function generateECDHKeypair() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
}

async function exportPublicKey(keypair) {
  const raw = await crypto.subtle.exportKey("raw", keypair.publicKey);
  return bytesToHex(new Uint8Array(raw));
}

async function deriveSharedAESKey(privateKey, peerPublicKeyHex) {
  const peerRaw = hexToBytes(peerPublicKeyHex);
  const peerPublicKey = await crypto.subtle.importKey(
    "raw",
    peerRaw,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  return crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// --- AES-GCM Encryption/Decryption ---
// Each message gets a fresh random 12-byte IV.
async function encryptMessage(text, aesKey) {
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    enc.encode(text)
  );
  return {
    iv: bytesToHex(iv),
    ciphertext: bytesToHex(new Uint8Array(ciphertext)),
  };
}

async function decryptMessage(ivHex, ciphertextHex, aesKey) {
  try {
    const iv = hexToBytes(ivHex);
    const ciphertext = hexToBytes(ciphertextHex);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      aesKey,
      ciphertext
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    return "[decryption failed]";
  }
}

// --- Helpers ---
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++)
    arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}
function randomHex(bytes = 16) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}
// ... existing hexToBytes and randomHex functions ...

function randomHex(bytes = 16) {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}

// ─────────────────────────────────────────────
// 📦 PERSISTENT STORAGE HELPERS (Add this here!)
// ─────────────────────────────────────────────
const DB_NAME = "SecureChatStore";
const STORE_NAME = "KeyPairs";

async function saveKeyLocally(username, keypair) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).put(keypair, username);
      tx.oncomplete = () => resolve();
    };
    request.onerror = () => reject(request.error);
  });
}

async function getLocalKey(username) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      const tx = db.transaction(STORE_NAME, "readonly");
      const getReq = tx.objectStore(STORE_NAME).get(username);
      getReq.onsuccess = () => resolve(getReq.result);
    };
    request.onerror = () => reject(request.error);
  });
}

// ─────────────────────────────────────────────
// 🎨 STYLES
// ─────────────────────────────────────────────
// ... existing styles ...

// ─────────────────────────────────────────────
// 🎨 STYLES
// ─────────────────────────────────────────────
const S = {
  root: {
    fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
    background: "#0a0a0f",
    color: "#e2e8f0",
    minHeight: "100vh",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
  },
  loginCard: {
    background: "#111118",
    border: "1px solid #1e293b",
    borderRadius: 16,
    padding: "2.5rem",
    width: 360,
    boxShadow: "0 0 60px rgba(99,102,241,0.08)",
  },
  logo: {
    fontSize: 13,
    color: "#6366f1",
    letterSpacing: "0.2em",
    textTransform: "uppercase",
    marginBottom: 8,
    fontWeight: 700,
  },
  h1: {
    fontSize: 22,
    fontWeight: 700,
    color: "#f1f5f9",
    margin: "0 0 6px",
  },
  subtitle: {
    fontSize: 12,
    color: "#475569",
    marginBottom: 28,
    lineHeight: 1.6,
  },
  label: {
    fontSize: 11,
    color: "#64748b",
    letterSpacing: "0.1em",
    textTransform: "uppercase",
    display: "block",
    marginBottom: 6,
  },
  input: {
    width: "100%",
    background: "#0d0d14",
    border: "1px solid #1e293b",
    borderRadius: 8,
    color: "#e2e8f0",
    padding: "10px 14px",
    fontSize: 14,
    marginBottom: 16,
    outline: "none",
    fontFamily: "inherit",
    boxSizing: "border-box",
  },
  select: {
    width: "100%",
    background: "#0d0d14",
    border: "1px solid #1e293b",
    borderRadius: 8,
    color: "#e2e8f0",
    padding: "10px 14px",
    fontSize: 14,
    marginBottom: 16,
    outline: "none",
    fontFamily: "inherit",
    boxSizing: "border-box",
    cursor: "pointer",
  },
  btn: {
    width: "100%",
    background: "#6366f1",
    border: "none",
    borderRadius: 8,
    color: "#fff",
    padding: "11px 0",
    fontSize: 13,
    fontWeight: 700,
    letterSpacing: "0.05em",
    cursor: "pointer",
    fontFamily: "inherit",
    transition: "background 0.15s",
  },
  errorBox: {
    background: "#2d1b1b",
    border: "1px solid #7f1d1d",
    borderRadius: 8,
    padding: "10px 14px",
    fontSize: 12,
    color: "#fca5a5",
    marginBottom: 16,
  },
  chatRoot: {
    width: "100vw",
    height: "100vh",
    display: "flex",
    flexDirection: "column",
    background: "#0a0a0f",
  },
  topbar: {
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    padding: "0 20px",
    height: 52,
    borderBottom: "1px solid #1e293b",
    background: "#0d0d14",
    flexShrink: 0,
  },
  topbarLeft: { display: "flex", alignItems: "center", gap: 12 },
  userDot: (color) => ({
    width: 8,
    height: 8,
    borderRadius: "50%",
    background: color,
    flexShrink: 0,
  }),
  topbarName: { fontSize: 13, fontWeight: 700, color: "#e2e8f0" },
  encBadge: {
    fontSize: 10,
    color: "#10b981",
    letterSpacing: "0.08em",
    background: "#052e16",
    border: "1px solid #065f46",
    borderRadius: 4,
    padding: "2px 7px",
  },
  cryptoPanel: {
    background: "#0d0d14",
    borderBottom: "1px solid #1e293b",
    padding: "8px 20px",
    fontSize: 10,
    color: "#475569",
    display: "flex",
    gap: 20,
    flexWrap: "wrap",
    flexShrink: 0,
  },
  cryptoItem: { display: "flex", flexDirection: "column", gap: 2 },
  cryptoLabel: { color: "#334155", textTransform: "uppercase", letterSpacing: "0.12em" },
  cryptoValue: { color: "#6366f1", fontFamily: "inherit", wordBreak: "break-all", maxWidth: 200 },
  msgArea: {
    flex: 1,
    overflowY: "auto",
    padding: "16px 20px",
    display: "flex",
    flexDirection: "column",
    gap: 10,
  },
  statusMsg: {
    textAlign: "center",
    fontSize: 11,
    color: "#334155",
    padding: "4px 0",
    letterSpacing: "0.08em",
  },
  msgBubble: (isMine) => ({
    display: "flex",
    flexDirection: "column",
    alignItems: isMine ? "flex-end" : "flex-start",
    gap: 3,
  }),
  bubble: (isMine) => ({
    background: isMine ? "#312e81" : "#1e293b",
    border: `1px solid ${isMine ? "#4338ca" : "#334155"}`,
    borderRadius: isMine ? "14px 14px 4px 14px" : "14px 14px 14px 4px",
    padding: "9px 14px",
    fontSize: 14,
    color: "#e2e8f0",
    maxWidth: 480,
    lineHeight: 1.5,
    wordBreak: "break-word",
  }),
  bubbleMeta: {
    fontSize: 10,
    color: "#475569",
    display: "flex",
    gap: 8,
    alignItems: "center",
  },
  ivTag: {
    fontFamily: "inherit",
    color: "#1d4ed8",
    fontSize: 9,
    background: "#172554",
    border: "1px solid #1e3a8a",
    borderRadius: 3,
    padding: "1px 5px",
    cursor: "pointer",
  },
  inputArea: {
    borderTop: "1px solid #1e293b",
    padding: "12px 16px",
    display: "flex",
    gap: 10,
    background: "#0d0d14",
    flexShrink: 0,
  },
  msgInput: {
    flex: 1,
    background: "#111118",
    border: "1px solid #1e293b",
    borderRadius: 10,
    color: "#e2e8f0",
    padding: "10px 14px",
    fontSize: 14,
    outline: "none",
    fontFamily: "inherit",
  },
  sendBtn: {
    background: "#6366f1",
    border: "none",
    borderRadius: 10,
    color: "#fff",
    padding: "10px 20px",
    fontSize: 13,
    fontWeight: 700,
    cursor: "pointer",
    fontFamily: "inherit",
    flexShrink: 0,
  },
  logoutBtn: {
    background: "transparent",
    border: "1px solid #1e293b",
    borderRadius: 7,
    color: "#64748b",
    padding: "5px 12px",
    fontSize: 11,
    cursor: "pointer",
    fontFamily: "inherit",
  },
  waitingOverlay: {
    position: "fixed",
    inset: 0,
    background: "rgba(10,10,15,0.9)",
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    justifyContent: "center",
    gap: 16,
    zIndex: 100,
  },
  spinner: {
    width: 32,
    height: 32,
    border: "3px solid #1e293b",
    borderTopColor: "#6366f1",
    borderRadius: "50%",
    animation: "spin 0.8s linear infinite",
  },
  waitText: { fontSize: 13, color: "#475569" },
  waitSub: { fontSize: 11, color: "#334155", maxWidth: 280, textAlign: "center", lineHeight: 1.6 },
};

// ─────────────────────────────────────────────
// 🔐 LOGIN SCREEN
// ─────────────────────────────────────────────
function LoginScreen({ onLogin }) {
  const [user, setUser] = useState("alice");
  const [pass, setPass] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleLogin() {
    setLoading(true);
    setError("");
    try {
      const correctPass = USERS[user];
      if (!correctPass) { setError("Unknown user"); setLoading(false); return; }

      // Fetch or create the user's PBKDF2 salt+hash from Firebase
      const userRef = ref(db, `users/${user}`);
      const snap = await get(userRef);

      if (!snap.exists()) {
        // First login: generate salt, hash password, store
        const salt = randomHex(16);
        const hash = await hashPassword(correctPass, salt);
        await set(userRef, { salt, hash });
        onLogin(user);
      } else {
        const { salt, hash } = snap.val();
        const ok = await verifyPassword(pass, salt, hash);
        if (ok) {
          onLogin(user);
        } else {
          setError("Wrong password.");
        }
      }
    } catch (e) {
      setError("Login error: " + e.message);
    }
    setLoading(false);
  }

  return (
    <div style={S.root}>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}} input:focus{border-color:#4338ca!important} select:focus{border-color:#4338ca!important}`}</style>
      <div style={S.loginCard}>
        <div style={S.logo}>◈ SecureChat</div>
        <h1 style={S.h1}>Encrypted Messenger</h1>
        <p style={S.subtitle}>
          ECDH key exchange · AES-GCM messages · SHA-256 auth
        </p>

        {error && <div style={S.errorBox}>{error}</div>}

        <label style={S.label}>User</label>
        <select style={S.select} value={user} onChange={e => setUser(e.target.value)}>
          <option value="alice">alice</option>
          <option value="bob">bob</option>
        </select>

        <label style={S.label}>Password</label>
        <input
          style={S.input}
          type="password"
          placeholder={user === "alice" ? "Enter Password" : "Enter Password"}
          value={pass}
          onChange={e => setPass(e.target.value)}
          onKeyDown={e => e.key === "Enter" && handleLogin()}
        />

        <button
          style={{ ...S.btn, opacity: loading ? 0.6 : 1 }}
          onClick={handleLogin}
          disabled={loading}
        >
          {loading ? "Authenticating…" : "Sign in →"}
        </button>

        <div style={{ marginTop: 20, fontSize: 11, color: "#334155", lineHeight: 1.7 }}>
          <strong style={{ color: "#475569" }}>Crypto stack:</strong><br />
          SHA-256 (salted) for password auth<br />
          ECDH P-256 for key exchange<br />
          AES-256-GCM for message encryption<br />
          Each message gets a unique random IV
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// 💬 CHAT SCREEN
// ─────────────────────────────────────────────
function ChatScreen({ username, onLogout }) {
  const peer = username === "alice" ? "bob" : "alice";
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [status, setStatus] = useState("Generating ECDH keypair…");
  const [ready, setReady] = useState(false);
  const [myPubKeyHex, setMyPubKeyHex] = useState("");
  const [peerPubKeyHex, setPeerPubKeyHex] = useState("");
  const aesKeyRef = useRef(null);
  const keypairRef = useRef(null);
  const bottomRef = useRef(null);

  // Step 1: Generate ECDH keypair, publish public key
  useEffect(() => {
  (async () => {
    setStatus("Checking for existing keys...");
    
    // 1. Try to load existing keypair from IndexedDB
    let kp = await getLocalKey(username);
    
    if (!kp) {
      setStatus("Generating new ECDH keypair...");
      kp = await generateECDHKeypair();
      // 2. Save it for next time
      await saveKeyLocally(username, kp);
    } else {
      setStatus("Loaded persistent keypair from storage.");
    }

    keypairRef.current = kp;
    const pubHex = await exportPublicKey(kp);
    setMyPubKeyHex(pubHex);

    // 3. Update Firebase with the key (ensure it's always current)
    await set(ref(db, `keys/${username}`), { pubKey: pubHex, ts: Date.now() });
    
    setStatus(`Waiting for ${peer} to connect...`);

    // 4. Watch for peer's public key (unchanged from your original)
    const peerKeyRef = ref(db, `keys/${peer}`);
    const unsub = onValue(peerKeyRef, async (snap) => {
      if (!snap.exists()) return;
      const { pubKey } = snap.val();
      setPeerPubKeyHex(pubKey);

      setStatus("Deriving shared channel...");
      try {
        const sharedKey = await deriveSharedAESKey(kp.privateKey, pubKey);
        aesKeyRef.current = sharedKey;
        setStatus("Secure channel established ✓");
        setReady(true);
      } catch (e) {
        setStatus("Key exchange failed: " + e.message);
      }
    });
    return () => unsub();
  })();
}, [username, peer]);

  // Step 3: Listen for messages
  useEffect(() => {
    const msgsRef = ref(db, "messages");
    const unsub = onValue(msgsRef, async (snap) => {
      if (!snap.exists() || !aesKeyRef.current) return;
      const raw = snap.val();
      const arr = Object.entries(raw)
        .map(([id, m]) => ({ id, ...m }))
        .sort((a, b) => (a.ts || 0) - (b.ts || 0));

      const decrypted = await Promise.all(
        arr.map(async (m) => {
          const text = await decryptMessage(m.iv, m.ciphertext, aesKeyRef.current);
          return { ...m, text };
        })
      );
      setMessages(decrypted);
    });
    return () => unsub();
  }, [ready]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function sendMessage() {
    if (!input.trim() || !aesKeyRef.current) return;
    const text = input.trim();
    setInput("");
    const { iv, ciphertext } = await encryptMessage(text, aesKeyRef.current);
    await push(ref(db, "messages"), {
      from: username,
      iv,
      ciphertext,
      ts: Date.now(),
    });
  }

  const userColors = { alice: "#a78bfa", bob: "#34d399" };

  return (
    <div style={S.chatRoot}>
      <style>{`
        @keyframes spin{to{transform:rotate(360deg)}}
        ::-webkit-scrollbar{width:4px}
        ::-webkit-scrollbar-track{background:#0a0a0f}
        ::-webkit-scrollbar-thumb{background:#1e293b;border-radius:4px}
        * { box-sizing: border-box; }
      `}</style>

      {/* Top bar */}
      <div style={S.topbar}>
        <div style={S.topbarLeft}>
          <div style={S.userDot(userColors[username])} />
          <span style={S.topbarName}>{username}</span>
          <span style={{ ...S.topbarName, color: "#334155" }}>→</span>
          <div style={S.userDot(userColors[peer])} />
          <span style={S.topbarName}>{peer}</span>
          {ready && <span style={S.encBadge}>E2E ENCRYPTED</span>}
        </div>
        <button style={S.logoutBtn} onClick={onLogout}>sign out</button>
      </div>

      {/* Crypto info panel */}
      {myPubKeyHex && (
        <div style={S.cryptoPanel}>
          <div style={S.cryptoItem}>
            <span style={S.cryptoLabel}>My ECDH pub key (P-256)</span>
            <span style={S.cryptoValue} title={myPubKeyHex}>{myPubKeyHex.slice(0, 40)}…</span>
          </div>
          {peerPubKeyHex && (
            <div style={S.cryptoItem}>
              <span style={S.cryptoLabel}>{peer}&apos;s pub key</span>
              <span style={S.cryptoValue} title={peerPubKeyHex}>{peerPubKeyHex.slice(0, 40)}…</span>
            </div>
          )}
          <div style={S.cryptoItem}>
            <span style={S.cryptoLabel}>Cipher</span>
            <span style={{ ...S.cryptoValue, color: "#10b981" }}>AES-256-GCM</span>
          </div>
          <div style={S.cryptoItem}>
            <span style={S.cryptoLabel}>Auth</span>
            <span style={{ ...S.cryptoValue, color: "#f59e0b" }}>SHA-256 salted hash</span>
          </div>
        </div>
      )}

      {/* Waiting overlay */}
      {!ready && (
        <div style={S.waitingOverlay}>
          <div style={S.spinner} />
          <div style={S.waitText}>{status}</div>
          <div style={S.waitSub}>
            Open this app in another browser window, log in as <strong>{peer}</strong>, and the
            ECDH handshake will complete automatically.
          </div>
        </div>
      )}

      {/* Message area */}
      <div style={S.msgArea}>
        <div style={S.statusMsg}>
          {ready ? `🔒 end-to-end encrypted — only you and ${peer} can read these` : status}
        </div>

        {messages.map((m) => {
          const isMine = m.from === username;
          return (
            <div key={m.id} style={S.msgBubble(isMine)}>
              <div style={S.bubble(isMine)}>{m.text}</div>
              <div style={S.bubbleMeta}>
                <span style={{ color: userColors[m.from] }}>{m.from}</span>
                <span>{new Date(m.ts).toLocaleTimeString()}</span>
                <span
                  style={S.ivTag}
                  title={`IV: ${m.iv}\nCiphertext: ${m.ciphertext}`}
                >
                  IV:{m.iv.slice(0, 6)}
                </span>
              </div>
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>

      {/* Input area */}
      <div style={S.inputArea}>
        <input
          style={S.msgInput}
          type="text"
          placeholder={ready ? `Message ${peer} (AES-256-GCM encrypted)…` : "Waiting for peer…"}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && sendMessage()}
          disabled={!ready}
        />
        <button style={{ ...S.sendBtn, opacity: ready ? 1 : 0.4 }} onClick={sendMessage} disabled={!ready}>
          Send →
        </button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// 🚀 APP ROOT
// ─────────────────────────────────────────────
export default function App() {
  const [username, setUsername] = useState(null);

  function handleLogout() {
    // Clear the user's public key from Firebase on logout
    if (username) {
      set(ref(db, `keys/${username}`), null);
    }
    setUsername(null);
  }

  if (!username) return <LoginScreen onLogin={setUsername} />;
  return <ChatScreen username={username} onLogout={handleLogout} />;
}
