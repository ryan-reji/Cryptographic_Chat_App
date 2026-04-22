// CryptChat.jsx — End-to-End Encrypted Chat with ECDH + AES-GCM + SHA-256
// Deploy on Vercel: just drop this into a Next.js or Vite React project.
// Requires Firebase (Realtime Database) for message relay.
//
// SETUP:
//  1. Create a Firebase project → enable Realtime Database (test mode initially)
//  2. Replace the firebaseConfig below with your project's config
//  3. npm install firebase
//  4. Deploy to Vercel
 
import { useState, useEffect, useRef } from "react";
import { initializeApp } from "firebase/app";
import {
  getDatabase,
  ref,
  push,
  onValue,
  set,
  get,
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
// 👥 USERS
// ─────────────────────────────────────────────
const USERS = {
  alice: "alice_password_123",
  bob: "bob_password_456",
};
 
// ─────────────────────────────────────────────
// 🔐 CRYPTOGRAPHY LAYER
// ─────────────────────────────────────────────
async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
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
    return "[DECRYPTION FAILED]";
  }
}
 
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
  if (typeof crypto === "undefined" || !crypto.getRandomValues) return "";
  return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes)));
}
 
// ─────────────────────────────────────────────
// 📦 PERSISTENT STORAGE
// ─────────────────────────────────────────────
const DB_NAME = "SecureChatStore";
const STORE_NAME = "KeyPairs";
 
async function saveKeyLocally(username, keypair) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME))
        request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => {
      const d = request.result;
      const tx = d.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).put(keypair, username);
      tx.oncomplete = () => resolve();
    };
    request.onerror = () => reject(request.error);
  });
}
 
async function getLocalKey(username) {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") return resolve(null);
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME))
        request.result.createObjectStore(STORE_NAME);
    };
    request.onsuccess = () => {
      const d = request.result;
      const tx = d.transaction(STORE_NAME, "readonly");
      const getReq = tx.objectStore(STORE_NAME).get(username);
      getReq.onsuccess = () => resolve(getReq.result);
    };
    request.onerror = () => reject(request.error);
  });
}
 
// ─────────────────────────────────────────────
// 🎨 DESIGN TOKENS — Warm Editorial / Paper
// ─────────────────────────────────────────────
const C = {
  paper:      "#F7F3EE",
  paperDark:  "#EDE8E0",
  paperDeep:  "#E0D9CE",
  ink:        "#1C1917",
  inkMid:     "#44403C",
  inkLight:   "#78716C",
  inkFaint:   "#A8A29E",
  border:     "#D6CFC4",
  borderDark: "#B5ADA2",
  alice:      "#7C3AED",   // violet
  aliceBg:    "#EDE9FE",
  bob:        "#0369A1",   // slate blue
  bobBg:      "#E0F2FE",
  accent:     "#92400E",   // warm brown
  accentBg:   "#FEF3C7",
  green:      "#15803D",
  greenBg:    "#DCFCE7",
  red:        "#B91C1C",
  redBg:      "#FEE2E2",
};
 
const FONT_SERIF  = "'Playfair Display', Georgia, serif";
const FONT_SANS   = "'DM Sans', 'Helvetica Neue', sans-serif";
const FONT_MONO   = "'JetBrains Mono', 'Fira Code', monospace";
 
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
      if (!correctPass) { setError("Unknown operator ID."); setLoading(false); return; }
 
      const userRef = ref(db, `users/${user}`);
      const snap = await get(userRef);
 
      if (!snap.exists()) {
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
          setError("Incorrect passphrase. Authentication denied.");
        }
      }
    } catch (e) {
      setError("System error: " + e.message);
    }
    setLoading(false);
  }
 
  return (
    <div style={{
      fontFamily: FONT_SANS,
      background: C.paper,
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      position: "relative",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=DM+Sans:wght@300;400;500&family=JetBrains+Mono:wght@400;500&display=swap');
 
        @keyframes fadeUp {
          from { opacity: 0; transform: translateY(16px); }
          to   { opacity: 1; transform: translateY(0); }
        }
        @keyframes shimmer {
          0%, 100% { opacity: 0.4; }
          50% { opacity: 0.9; }
        }
 
        .login-card { animation: fadeUp 0.5s ease both; }
 
        .field-input {
          width: 100%;
          background: white;
          border: 1.5px solid ${C.border};
          color: ${C.ink};
          padding: 11px 14px;
          font-size: 14px;
          font-family: ${FONT_SANS};
          outline: none;
          border-radius: 8px;
          transition: border-color 0.15s, box-shadow 0.15s;
          box-sizing: border-box;
        }
        .field-input:focus {
          border-color: ${C.accent};
          box-shadow: 0 0 0 3px ${C.accentBg};
        }
        .field-select {
          appearance: none;
          background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%2378716C' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
          background-repeat: no-repeat;
          background-position: right 12px center;
          cursor: pointer;
        }
        .auth-btn {
          width: 100%;
          background: ${C.ink};
          border: none;
          color: ${C.paper};
          padding: 12px 0;
          font-size: 13px;
          font-family: ${FONT_SANS};
          font-weight: 500;
          letter-spacing: 0.06em;
          cursor: pointer;
          border-radius: 8px;
          transition: background 0.15s, transform 0.1s;
        }
        .auth-btn:hover { background: ${C.inkMid}; }
        .auth-btn:active { transform: scale(0.99); }
        .auth-btn:disabled { background: ${C.inkFaint}; cursor: not-allowed; }
 
        select option { background: white; color: ${C.ink}; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: ${C.paper}; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 4px; }
      `}</style>
 
      {/* Subtle ruled-paper lines in background */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none",
        backgroundImage: `repeating-linear-gradient(transparent, transparent 27px, ${C.paperDeep} 27px, ${C.paperDeep} 28px)`,
        opacity: 0.5,
      }} />
 
      {/* Left margin line */}
      <div style={{
        position: "fixed", left: "12%", top: 0, bottom: 0, width: 1,
        background: `${C.alice}30`, pointerEvents: "none",
      }} />
 
      <div className="login-card" style={{
        width: 380,
        background: "white",
        border: `1.5px solid ${C.border}`,
        borderRadius: 16,
        overflow: "hidden",
        boxShadow: `0 2px 0 ${C.paperDeep}, 0 4px 0 ${C.border}, 0 20px 60px rgba(0,0,0,0.08)`,
        position: "relative",
        zIndex: 1,
      }}>
        {/* Colored top stripe */}
        <div style={{
          height: 4,
          background: `linear-gradient(90deg, ${C.alice} 0%, ${C.bob} 100%)`,
        }} />
 
        <div style={{ padding: "32px 32px 36px" }}>
          {/* Logo */}
          <div style={{ marginBottom: 32 }}>
            <div style={{
              display: "flex", alignItems: "center", gap: 10, marginBottom: 6,
            }}>
              <div style={{
                width: 32, height: 32,
                background: C.ink,
                borderRadius: 8,
                display: "flex", alignItems: "center", justifyContent: "center",
              }}>
                <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                  <rect x="2" y="4" width="12" height="9" rx="2" stroke="white" strokeWidth="1.5"/>
                  <path d="M5 4V3a3 3 0 016 0v1" stroke="white" strokeWidth="1.5" strokeLinecap="round"/>
                  <circle cx="8" cy="8.5" r="1.5" fill="white"/>
                  <path d="M8 10v2" stroke="white" strokeWidth="1.5" strokeLinecap="round"/>
                </svg>
              </div>
              <span style={{
                fontFamily: FONT_SERIF,
                fontSize: 22,
                fontWeight: 600,
                color: C.ink,
                letterSpacing: "-0.02em",
              }}>
                CryptChat
              </span>
            </div>
            <p style={{
              fontSize: 12,
              color: C.inkLight,
              margin: 0,
              fontFamily: FONT_MONO,
              letterSpacing: "0.02em",
            }}>
              ECDH P-256 · AES-256-GCM · SHA-256
            </p>
          </div>
 
          {/* Error */}
          {error && (
            <div style={{
              background: C.redBg,
              border: `1px solid #FECACA`,
              borderLeft: `3px solid ${C.red}`,
              borderRadius: 8,
              padding: "10px 14px",
              fontSize: 13,
              color: C.red,
              marginBottom: 20,
              lineHeight: 1.5,
            }}>
              {error}
            </div>
          )}
 
          {/* Operator ID */}
          <div style={{ marginBottom: 16 }}>
            <label style={{
              display: "block",
              fontSize: 11,
              fontWeight: 500,
              color: C.inkLight,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              marginBottom: 6,
            }}>
              Operator
            </label>
            <select
              className="field-input field-select"
              value={user}
              onChange={e => setUser(e.target.value)}
            >
              <option value="alice">Alice</option>
              <option value="bob">Bob</option>
            </select>
          </div>
 
          {/* Passphrase */}
          <div style={{ marginBottom: 24 }}>
            <label style={{
              display: "block",
              fontSize: 11,
              fontWeight: 500,
              color: C.inkLight,
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              marginBottom: 6,
            }}>
              Passphrase
            </label>
            <input
              type="password"
              placeholder="Enter clearance code"
              value={pass}
              onChange={e => setPass(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleLogin()}
              className="field-input"
            />
          </div>
 
          {/* Auth button */}
          <button
            onClick={handleLogin}
            disabled={loading}
            className="auth-btn"
          >
            {loading ? "Authenticating…" : "Sign in →"}
          </button>
 
          {/* Crypto footer */}
          <div style={{
            marginTop: 24,
            paddingTop: 20,
            borderTop: `1px solid ${C.border}`,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "8px 20px",
          }}>
            {[
              ["Auth", "SHA-256 salted"],
              ["Key exchange", "ECDH P-256"],
              ["Cipher", "AES-256-GCM"],
              ["IV", "96-bit random"],
            ].map(([k, v]) => (
              <div key={k}>
                <div style={{ fontSize: 10, color: C.inkFaint, marginBottom: 1 }}>{k}</div>
                <div style={{ fontSize: 11, color: C.inkMid, fontFamily: FONT_MONO }}>{v}</div>
              </div>
            ))}
          </div>
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
  const [status, setStatus] = useState("Initializing ECDH subsystem…");
  const [ready, setReady] = useState(false);
  const [myPubKeyHex, setMyPubKeyHex] = useState("");
  const [peerPubKeyHex, setPeerPubKeyHex] = useState("");
  const aesKeyRef = useRef(null);
  const keypairRef = useRef(null);
  const bottomRef = useRef(null);
  const [time, setTime] = useState(new Date());
 
  const userColor = { alice: C.alice, bob: C.bob };
  const userBg = { alice: C.aliceBg, bob: C.bobBg };
 
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
 
  useEffect(() => {
    (async () => {
      setStatus("Checking local key store…");
      let kp = await getLocalKey(username);
      if (!kp) {
        setStatus("Generating ECDH keypair…");
        kp = await generateECDHKeypair();
        await saveKeyLocally(username, kp);
      } else {
        setStatus("Persistent keypair loaded.");
      }
      keypairRef.current = kp;
      const pubHex = await exportPublicKey(kp);
      setMyPubKeyHex(pubHex);
      await set(ref(db, `keys/${username}`), { pubKey: pubHex, ts: Date.now() });
      setStatus(`Awaiting peer (${peer})…`);
 
      const peerKeyRef = ref(db, `keys/${peer}`);
      const unsub = onValue(peerKeyRef, async (snap) => {
        if (!snap.exists()) return;
        const { pubKey } = snap.val();
        setPeerPubKeyHex(pubKey);
        setStatus("Deriving shared channel…");
        try {
          const sharedKey = await deriveSharedAESKey(kp.privateKey, pubKey);
          aesKeyRef.current = sharedKey;
          setStatus("Secure channel established");
          setReady(true);
        } catch (e) {
          setStatus("Key exchange failed: " + e.message);
        }
      });
      return () => unsub();
    })();
  }, [username, peer]);
 
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
 
  // Avatar initials
  const initials = (name) => name[0].toUpperCase();
 
  return (
    <div style={{
      fontFamily: FONT_SANS,
      background: C.paper,
      width: "100vw",
      height: "100vh",
      display: "flex",
      flexDirection: "column",
      overflow: "hidden",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=DM+Sans:wght@300;400;500&family=JetBrains+Mono:wght@400;500&display=swap');
 
        @keyframes fadeUp { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes spin { to{transform:rotate(360deg)} }
        @keyframes slideIn { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:none} }
 
        .msg-row { animation: slideIn 0.2s ease both; }
 
        .send-btn {
          background: ${C.ink};
          border: none;
          color: white;
          padding: 0 20px;
          height: 42px;
          font-size: 13px;
          font-family: ${FONT_SANS};
          font-weight: 500;
          border-radius: 10px;
          cursor: pointer;
          transition: background 0.15s, transform 0.1s;
          white-space: nowrap;
        }
        .send-btn:hover { background: ${C.inkMid}; }
        .send-btn:active { transform: scale(0.98); }
        .send-btn:disabled { background: ${C.inkFaint}; cursor: not-allowed; }
 
        .msg-input {
          flex: 1;
          background: white;
          border: 1.5px solid ${C.border};
          color: ${C.ink};
          padding: 10px 14px;
          font-size: 14px;
          font-family: ${FONT_SANS};
          outline: none;
          border-radius: 10px;
          transition: border-color 0.15s, box-shadow 0.15s;
        }
        .msg-input:focus {
          border-color: ${C.accent};
          box-shadow: 0 0 0 3px ${C.accentBg};
        }
        .msg-input:disabled { opacity: 0.5; cursor: not-allowed; }
 
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${C.border}; border-radius: 4px; }
 
        .signout-btn {
          background: transparent;
          border: 1px solid ${C.border};
          color: ${C.inkLight};
          padding: 5px 12px;
          font-size: 12px;
          font-family: ${FONT_SANS};
          border-radius: 6px;
          cursor: pointer;
          transition: background 0.12s, color 0.12s;
        }
        .signout-btn:hover { background: ${C.paperDark}; color: ${C.ink}; }
      `}</style>
 
      {/* ── TOPBAR ── */}
      <div style={{
        background: "white",
        borderBottom: `1px solid ${C.border}`,
        padding: "0 20px",
        height: 56,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexShrink: 0,
      }}>
        {/* Left: Logo + participants */}
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{
              width: 28, height: 28,
              background: C.ink,
              borderRadius: 7,
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                <rect x="2" y="4" width="12" height="9" rx="2" stroke="white" strokeWidth="1.5"/>
                <path d="M5 4V3a3 3 0 016 0v1" stroke="white" strokeWidth="1.5" strokeLinecap="round"/>
                <circle cx="8" cy="8.5" r="1.5" fill="white"/>
                <path d="M8 10v2" stroke="white" strokeWidth="1.5" strokeLinecap="round"/>
              </svg>
            </div>
            <span style={{
              fontFamily: FONT_SERIF,
              fontSize: 17,
              fontWeight: 600,
              color: C.ink,
              letterSpacing: "-0.01em",
            }}>
              CryptChat
            </span>
          </div>
 
          <div style={{ width: 1, height: 20, background: C.border }} />
 
          {/* Participants */}
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            {[username, peer].map((u, i) => (
              <div key={u} style={{ display: "flex", alignItems: "center", gap: i === 1 ? 0 : 6 }}>
                {i === 1 && (
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" style={{ marginRight: 6, color: C.inkFaint }}>
                    <path d="M3 7h8M7.5 4l3.5 3-3.5 3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                )}
                <div style={{
                  width: 26, height: 26,
                  borderRadius: "50%",
                  background: userBg[u],
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 11,
                  fontWeight: 500,
                  color: userColor[u],
                  border: u === username ? `2px solid ${userColor[u]}` : `1px solid ${userColor[u]}40`,
                }}>
                  {initials(u)}
                </div>
                <span style={{
                  fontSize: 13,
                  color: u === username ? C.ink : C.inkLight,
                  fontWeight: u === username ? 500 : 400,
                }}>
                  {u.charAt(0).toUpperCase() + u.slice(1)}
                </span>
              </div>
            ))}
          </div>
 
          {ready && (
            <div style={{
              display: "flex", alignItems: "center", gap: 5,
              background: C.greenBg,
              border: `1px solid #BBF7D0`,
              borderRadius: 20,
              padding: "3px 10px",
            }}>
              <div style={{
                width: 6, height: 6,
                borderRadius: "50%",
                background: C.green,
                animation: "pulse 2.5s ease infinite",
              }} />
              <span style={{ fontSize: 11, color: C.green, fontWeight: 500 }}>E2E Secure</span>
            </div>
          )}
        </div>
 
        {/* Right: Time + sign out */}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{
            fontSize: 12,
            color: C.inkFaint,
            fontFamily: FONT_MONO,
          }}>
            {time.toLocaleTimeString("en-US", { hour12: false })}
          </span>
          <button onClick={onLogout} className="signout-btn">
            Sign out
          </button>
        </div>
      </div>
 
      {/* ── CRYPTO INFO STRIP ── */}
      {myPubKeyHex && (
        <div style={{
          background: C.paperDark,
          borderBottom: `1px solid ${C.border}`,
          padding: "6px 20px",
          display: "flex",
          gap: 28,
          flexShrink: 0,
          overflowX: "auto",
          alignItems: "center",
        }}>
          {[
            ["My pubkey (P-256)", myPubKeyHex.slice(0, 44) + "…"],
            peerPubKeyHex ? [`${peer.charAt(0).toUpperCase() + peer.slice(1)}'s pubkey`, peerPubKeyHex.slice(0, 44) + "…"] : null,
            ["Cipher", "AES-256-GCM"],
            ["Auth", "SHA-256 salted"],
          ].filter(Boolean).map(([label, val]) => (
            <div key={label} style={{ flexShrink: 0, display: "flex", gap: 8, alignItems: "baseline" }}>
              <span style={{ fontSize: 10, color: C.inkFaint }}>{label}</span>
              <span style={{
                fontSize: 10,
                color: label === "Cipher" ? C.green : label === "Auth" ? C.accent : C.inkLight,
                fontFamily: FONT_MONO,
                maxWidth: 200,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}>{val}</span>
            </div>
          ))}
        </div>
      )}
 
      {/* ── WAITING OVERLAY ── */}
      {!ready && (
        <div style={{
          position: "fixed", inset: 0,
          background: "rgba(247,243,238,0.92)",
          display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center",
          gap: 16, zIndex: 40,
          backdropFilter: "blur(2px)",
        }}>
          <div style={{
            width: 32, height: 32,
            border: `2px solid ${C.border}`,
            borderTopColor: C.ink,
            borderRadius: "50%",
            animation: "spin 0.8s linear infinite",
          }} />
          <div style={{
            fontFamily: FONT_SANS,
            fontSize: 15,
            fontWeight: 500,
            color: C.ink,
          }}>
            {status}
          </div>
          <div style={{
            fontSize: 13, color: C.inkLight, maxWidth: 320,
            textAlign: "center", lineHeight: 1.7,
          }}>
            Open a second browser window · Log in as{" "}
            <span style={{ color: userColor[peer], fontWeight: 500 }}>
              {peer.charAt(0).toUpperCase() + peer.slice(1)}
            </span>{" "}
            · ECDH handshake will complete automatically.
          </div>
        </div>
      )}
 
      {/* ── MESSAGE AREA ── */}
      <div style={{
        flex: 1, overflowY: "auto",
        padding: "20px 24px",
        display: "flex", flexDirection: "column", gap: 6,
        background: C.paper,
      }}>
        {/* Channel header */}
        <div style={{
          textAlign: "center",
          margin: "0 0 16px",
        }}>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 10,
            background: "white",
            border: `1px solid ${C.border}`,
            borderRadius: 20,
            padding: "6px 16px",
          }}>
            {ready ? (
              <>
                <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.green }} />
                <span style={{ fontSize: 11, color: C.inkLight }}>
                  Channel secure — only {username} & {peer} can decrypt
                </span>
              </>
            ) : (
              <span style={{ fontSize: 11, color: C.inkLight }}>{status}</span>
            )}
          </div>
        </div>
 
        {messages.map((m) => {
          const isMine = m.from === username;
          const color = userColor[m.from];
          const bg = userBg[m.from];
          return (
            <div key={m.id} className="msg-row" style={{
              display: "flex",
              flexDirection: "column",
              alignItems: isMine ? "flex-end" : "flex-start",
              gap: 4,
            }}>
              {/* Meta */}
              <div style={{
                display: "flex", gap: 8, alignItems: "center",
                flexDirection: isMine ? "row-reverse" : "row",
              }}>
                <div style={{
                  width: 22, height: 22, borderRadius: "50%",
                  background: bg,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 10, fontWeight: 500, color,
                }}>
                  {initials(m.from)}
                </div>
                <span style={{ fontSize: 11, color: C.inkFaint }}>
                  {new Date(m.ts).toLocaleTimeString("en-US", { hour12: true, hour: "numeric", minute: "2-digit" })}
                </span>
                <span
                  style={{
                    fontSize: 10,
                    color: C.inkFaint,
                    background: C.paperDark,
                    border: `1px solid ${C.border}`,
                    borderRadius: 4,
                    padding: "1px 6px",
                    fontFamily: FONT_MONO,
                    cursor: "default",
                  }}
                  title={`IV: ${m.iv}\nCiphertext: ${m.ciphertext}`}
                >
                  IV:{m.iv.slice(0, 8)}
                </span>
              </div>
              {/* Bubble */}
              <div style={{
                background: isMine ? "white" : C.paper,
                border: `1px solid ${isMine ? C.border : C.paperDeep}`,
                borderLeft: !isMine ? `3px solid ${color}` : undefined,
                borderRight: isMine ? `3px solid ${color}` : undefined,
                borderRadius: 10,
                padding: "10px 14px",
                fontSize: 14,
                color: C.ink,
                maxWidth: 520,
                lineHeight: 1.6,
                wordBreak: "break-word",
                boxShadow: "0 1px 2px rgba(0,0,0,0.04)",
              }}>
                {m.text}
              </div>
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>
 
      {/* ── INPUT AREA ── */}
      <div style={{
        borderTop: `1px solid ${C.border}`,
        background: "white",
        padding: "12px 20px",
        display: "flex", gap: 10,
        flexShrink: 0,
        alignItems: "center",
      }}>
        {/* Lock icon */}
        <div style={{ flexShrink: 0 }}>
          {ready ? (
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <rect x="2" y="7" width="12" height="8" rx="2" fill={C.green} opacity="0.15" stroke={C.green} strokeWidth="1.3"/>
              <path d="M5 7V5a3 3 0 016 0v2" stroke={C.green} strokeWidth="1.3" strokeLinecap="round"/>
              <circle cx="8" cy="11" r="1" fill={C.green}/>
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <rect x="2" y="7" width="12" height="8" rx="2" stroke={C.inkFaint} strokeWidth="1.3"/>
              <path d="M5 7V5a3 3 0 016 0v2" stroke={C.inkFaint} strokeWidth="1.3" strokeLinecap="round"/>
            </svg>
          )}
        </div>
 
        <input
          type="text"
          placeholder={
            ready
              ? `Message ${peer.charAt(0).toUpperCase() + peer.slice(1)} — encrypted with AES-256-GCM`
              : "Waiting for peer connection…"
          }
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && sendMessage()}
          disabled={!ready}
          className="msg-input"
        />
        <button
          onClick={sendMessage}
          disabled={!ready}
          className="send-btn"
        >
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
    if (username) set(ref(db, `keys/${username}`), null);
    setUsername(null);
  }
 
  if (!username) return <LoginScreen onLogin={setUsername} />;
  return <ChatScreen username={username} onLogout={handleLogout} />;
}
