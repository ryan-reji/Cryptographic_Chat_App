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
// 🎨 DESIGN TOKENS
// ─────────────────────────────────────────────
const C = {
  bg:       "#06060A",
  bgPanel:  "#0C0C12",
  bgInput:  "#080810",
  amber:    "#D4941A",
  amberDim: "#8A5E0A",
  amberGlow:"#F5B942",
  red:      "#C0392B",
  redDim:   "#6B1A14",
  green:    "#27AE60",
  greenDim: "#0D4D28",
  border:   "#1E1E2E",
  borderLit:"#3A3A5C",
  muted:    "#3A3A4A",
  mutedText:"#6A6A8A",
  alice:    "#D4941A",  // amber
  bob:      "#5DADE2",  // steel blue
};

const FONT_MONO  = "'Share Tech Mono', 'Courier New', monospace";
const FONT_TITLE = "'Orbitron', monospace";

// ─────────────────────────────────────────────
// 🔐 LOGIN SCREEN
// ─────────────────────────────────────────────
function LoginScreen({ onLogin }) {
  const [user, setUser] = useState("alice");
  const [pass, setPass] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [tick, setTick] = useState(true);

  useEffect(() => {
    const t = setInterval(() => setTick(v => !v), 530);
    return () => clearInterval(t);
  }, []);

  async function handleLogin() {
    setLoading(true);
    setError("");
    try {
      const correctPass = USERS[user];
      if (!correctPass) { setError("UNKNOWN OPERATOR ID"); setLoading(false); return; }

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
          setError("AUTHENTICATION FAILURE — ACCESS DENIED");
        }
      }
    } catch (e) {
      setError("SYSTEM ERROR: " + e.message);
    }
    setLoading(false);
  }

  return (
    <div style={{
      fontFamily: FONT_MONO,
      background: C.bg,
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      position: "relative",
      overflow: "hidden",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
        @keyframes scanline {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }
        @keyframes flicker {
          0%,100% { opacity: 1; }
          92% { opacity: 1; }
          93% { opacity: 0.6; }
          94% { opacity: 1; }
          96% { opacity: 0.8; }
          97% { opacity: 1; }
        }
        @keyframes glitch {
          0%,100% { clip-path: none; transform: none; }
          2% { clip-path: inset(30% 0 50% 0); transform: translate(-4px, 0); }
          4% { clip-path: none; transform: none; }
          6% { clip-path: inset(70% 0 10% 0); transform: translate(4px, 0); }
          8% { clip-path: none; transform: none; }
        }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:none} }
        @keyframes spin { to { transform: rotate(360deg); } }
        .login-panel {
          animation: flicker 8s infinite, fadeIn 0.4s ease both;
        }
        .logo-glitch {
          animation: glitch 6s infinite;
        }
        input:-webkit-autofill {
          -webkit-box-shadow: 0 0 0 1000px ${C.bgInput} inset !important;
          -webkit-text-fill-color: ${C.amber} !important;
        }
        select option { background: ${C.bgInput}; color: ${C.amber}; }
        ::-webkit-scrollbar { width: 3px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.amberDim}; }
      `}</style>

      {/* Scanline sweep */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 50,
        background: "repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.18) 2px, rgba(0,0,0,0.18) 4px)",
      }} />
      <div style={{
        position: "fixed", left: 0, right: 0, height: "40px", pointerEvents: "none", zIndex: 49,
        background: "linear-gradient(transparent, rgba(212,148,26,0.04), transparent)",
        animation: "scanline 4s linear infinite",
      }} />

      {/* Corner decorations */}
      {[
        { top: 24, left: 24 },
        { top: 24, right: 24 },
        { bottom: 24, left: 24 },
        { bottom: 24, right: 24 },
      ].map((pos, i) => (
        <div key={i} style={{
          position: "fixed", ...pos,
          width: 24, height: 24, pointerEvents: "none",
          borderTop: i < 2 ? `1px solid ${C.amberDim}` : "none",
          borderBottom: i >= 2 ? `1px solid ${C.amberDim}` : "none",
          borderLeft: i % 2 === 0 ? `1px solid ${C.amberDim}` : "none",
          borderRight: i % 2 === 1 ? `1px solid ${C.amberDim}` : "none",
        }} />
      ))}

      <div className="login-panel" style={{
        width: 400,
        border: `1px solid ${C.borderLit}`,
        background: C.bgPanel,
        padding: "0",
        position: "relative",
      }}>
        {/* Header bar */}
        <div style={{
          background: C.amber,
          padding: "6px 16px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
        }}>
          <span style={{ fontFamily: FONT_TITLE, fontSize: 9, fontWeight: 900, color: C.bg, letterSpacing: "0.3em" }}>
            CRYPTCHAT
          </span>
          <span style={{ fontSize: 9, color: C.bg, letterSpacing: "0.15em", opacity: 0.7 }}>
            SECURE COMMS v2.4
          </span>
        </div>

        {/* Classified stamp area */}
        <div style={{
          borderBottom: `1px solid ${C.border}`,
          padding: "14px 24px 12px",
          display: "flex",
          alignItems: "center",
          gap: 12,
        }}>
          <div style={{
            border: `2px solid ${C.red}`,
            padding: "3px 8px",
            fontSize: 9,
            fontWeight: 700,
            color: C.red,
            letterSpacing: "0.25em",
            lineHeight: 1,
          }}>
            CLASSIFIED
          </div>
          <div style={{ fontSize: 10, color: C.mutedText, letterSpacing: "0.1em" }}>
            AUTHORIZED PERSONNEL ONLY
          </div>
        </div>

        <div style={{ padding: "24px 24px 28px" }}>
          {/* Logo */}
          <div style={{ marginBottom: 28, position: "relative" }}>
            <div className="logo-glitch" style={{
              fontFamily: FONT_TITLE,
              fontSize: 28,
              fontWeight: 900,
              color: C.amberGlow,
              letterSpacing: "0.12em",
              lineHeight: 1,
              textShadow: `0 0 20px ${C.amber}55, 0 0 40px ${C.amber}22`,
            }}>
              CRYPT<span style={{ color: C.amber }}>CHAT</span>
            </div>
            <div style={{ fontSize: 10, color: C.mutedText, marginTop: 6, letterSpacing: "0.15em" }}>
              E2E-ENCRYPTED · ECDH P-256 · AES-256-GCM
            </div>
          </div>

          {/* Error */}
          {error && (
            <div style={{
              background: C.redDim,
              border: `1px solid ${C.red}`,
              padding: "8px 12px",
              fontSize: 11,
              color: "#E88",
              marginBottom: 16,
              letterSpacing: "0.05em",
            }}>
              ▲ {error}
            </div>
          )}

          {/* Operator ID */}
          <div style={{ marginBottom: 14 }}>
            <label style={{
              display: "block",
              fontSize: 9,
              color: C.mutedText,
              letterSpacing: "0.2em",
              marginBottom: 6,
              textTransform: "uppercase",
            }}>
              ▸ OPERATOR ID
            </label>
            <select
              style={{
                width: "100%",
                background: C.bgInput,
                border: `1px solid ${C.borderLit}`,
                color: C.amber,
                padding: "9px 12px",
                fontSize: 13,
                fontFamily: FONT_MONO,
                letterSpacing: "0.1em",
                outline: "none",
                cursor: "pointer",
                appearance: "none",
              }}
              value={user}
              onChange={e => setUser(e.target.value)}
            >
              <option value="alice">ALICE</option>
              <option value="bob">BOB</option>
            </select>
          </div>

          {/* Passphrase */}
          <div style={{ marginBottom: 20 }}>
            <label style={{
              display: "block",
              fontSize: 9,
              color: C.mutedText,
              letterSpacing: "0.2em",
              marginBottom: 6,
              textTransform: "uppercase",
            }}>
              ▸ PASSPHRASE
            </label>
            <div style={{ position: "relative" }}>
              <input
                type="password"
                placeholder="ENTER CLEARANCE CODE"
                value={pass}
                onChange={e => setPass(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleLogin()}
                style={{
                  width: "100%",
                  background: C.bgInput,
                  border: `1px solid ${C.borderLit}`,
                  color: C.amber,
                  padding: "9px 12px",
                  fontSize: 13,
                  fontFamily: FONT_MONO,
                  letterSpacing: "0.15em",
                  outline: "none",
                }}
              />
              <span style={{
                position: "absolute",
                right: 10,
                top: "50%",
                transform: "translateY(-50%)",
                color: C.amber,
                fontSize: 14,
                animation: "blink 1.1s step-end infinite",
                opacity: tick ? 1 : 0,
              }}>▌</span>
            </div>
          </div>

          {/* Auth button */}
          <button
            onClick={handleLogin}
            disabled={loading}
            style={{
              width: "100%",
              background: loading ? C.amberDim : C.amber,
              border: "none",
              color: C.bg,
              padding: "11px 0",
              fontSize: 11,
              fontFamily: FONT_TITLE,
              fontWeight: 700,
              letterSpacing: "0.3em",
              cursor: loading ? "not-allowed" : "pointer",
              transition: "background 0.15s",
            }}
          >
            {loading ? "AUTHENTICATING..." : "AUTHENTICATE →"}
          </button>

          {/* Crypto footer */}
          <div style={{
            marginTop: 20,
            borderTop: `1px solid ${C.border}`,
            paddingTop: 14,
            display: "grid",
            gridTemplateColumns: "1fr 1fr",
            gap: "6px 16px",
          }}>
            {[
              ["AUTH", "SHA-256 SALTED"],
              ["KEX", "ECDH P-256"],
              ["CIPHER", "AES-256-GCM"],
              ["IV", "96-BIT RANDOM"],
            ].map(([k, v]) => (
              <div key={k} style={{ display: "flex", gap: 6, alignItems: "baseline" }}>
                <span style={{ fontSize: 8, color: C.mutedText, letterSpacing: "0.15em", flexShrink: 0 }}>{k}</span>
                <span style={{ fontSize: 8, color: C.amberDim, letterSpacing: "0.05em" }}>{v}</span>
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
  const [status, setStatus] = useState("INITIALIZING ECDH SUBSYSTEM...");
  const [ready, setReady] = useState(false);
  const [myPubKeyHex, setMyPubKeyHex] = useState("");
  const [peerPubKeyHex, setPeerPubKeyHex] = useState("");
  const aesKeyRef = useRef(null);
  const keypairRef = useRef(null);
  const bottomRef = useRef(null);
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    (async () => {
      setStatus("CHECKING LOCAL KEY STORE...");
      let kp = await getLocalKey(username);
      if (!kp) {
        setStatus("GENERATING ECDH KEYPAIR...");
        kp = await generateECDHKeypair();
        await saveKeyLocally(username, kp);
      } else {
        setStatus("PERSISTENT KEYPAIR LOADED.");
      }
      keypairRef.current = kp;
      const pubHex = await exportPublicKey(kp);
      setMyPubKeyHex(pubHex);
      await set(ref(db, `keys/${username}`), { pubKey: pubHex, ts: Date.now() });
      setStatus(`AWAITING PEER [${peer.toUpperCase()}]...`);

      const peerKeyRef = ref(db, `keys/${peer}`);
      const unsub = onValue(peerKeyRef, async (snap) => {
        if (!snap.exists()) return;
        const { pubKey } = snap.val();
        setPeerPubKeyHex(pubKey);
        setStatus("DERIVING SHARED CHANNEL...");
        try {
          const sharedKey = await deriveSharedAESKey(kp.privateKey, pubKey);
          aesKeyRef.current = sharedKey;
          setStatus("SECURE CHANNEL ESTABLISHED");
          setReady(true);
        } catch (e) {
          setStatus("KEY EXCHANGE FAILED: " + e.message);
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

  const userColor = { alice: C.alice, bob: C.bob };

  return (
    <div style={{
      fontFamily: FONT_MONO,
      background: C.bg,
      width: "100vw",
      height: "100vh",
      display: "flex",
      flexDirection: "column",
      position: "relative",
      overflow: "hidden",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;700;900&display=swap');
        @keyframes scanline {
          0% { transform: translateY(-100%); }
          100% { transform: translateY(100vh); }
        }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }
        @keyframes fadeSlide { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:none} }
        ::-webkit-scrollbar { width: 3px; }
        ::-webkit-scrollbar-track { background: ${C.bg}; }
        ::-webkit-scrollbar-thumb { background: ${C.amberDim}; }
        input:-webkit-autofill {
          -webkit-box-shadow: 0 0 0 1000px ${C.bgInput} inset !important;
          -webkit-text-fill-color: ${C.amber} !important;
        }
        .msg-in { animation: fadeSlide 0.2s ease both; }
      `}</style>

      {/* Scanlines */}
      <div style={{
        position: "fixed", inset: 0, pointerEvents: "none", zIndex: 50,
        background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.14) 2px,rgba(0,0,0,0.14) 4px)",
      }} />
      <div style={{
        position: "fixed", left: 0, right: 0, height: "60px", pointerEvents: "none", zIndex: 49,
        background: "linear-gradient(transparent,rgba(212,148,26,0.03),transparent)",
        animation: "scanline 5s linear infinite",
      }} />

      {/* ── TOPBAR ── */}
      <div style={{
        background: C.bgPanel,
        borderBottom: `1px solid ${C.border}`,
        padding: "0 16px",
        height: 48,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexShrink: 0,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{
            fontFamily: FONT_TITLE,
            fontSize: 13,
            fontWeight: 900,
            color: C.amberGlow,
            letterSpacing: "0.15em",
            textShadow: `0 0 12px ${C.amber}44`,
          }}>
            CRYPT<span style={{ color: C.amber }}>CHAT</span>
          </span>

          <div style={{ width: 1, height: 20, background: C.border }} />

          {/* Operator badges */}
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{
              fontSize: 9, letterSpacing: "0.2em",
              color: userColor[username],
              border: `1px solid ${userColor[username]}55`,
              padding: "2px 7px",
            }}>
              {username.toUpperCase()}
            </span>
            <span style={{ fontSize: 9, color: C.mutedText }}>⟶</span>
            <span style={{
              fontSize: 9, letterSpacing: "0.2em",
              color: userColor[peer],
              border: `1px solid ${userColor[peer]}55`,
              padding: "2px 7px",
            }}>
              {peer.toUpperCase()}
            </span>
          </div>

          {ready && (
            <div style={{
              fontSize: 8,
              color: C.green,
              border: `1px solid ${C.greenDim}`,
              padding: "2px 8px",
              letterSpacing: "0.15em",
              animation: "pulse 3s ease infinite",
            }}>
              ● E2E SECURE
            </div>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <span style={{ fontSize: 9, color: C.mutedText, letterSpacing: "0.1em", fontFamily: FONT_TITLE }}>
            {time.toLocaleTimeString("en-US", { hour12: false })}
          </span>
          <button
            onClick={onLogout}
            style={{
              background: "transparent",
              border: `1px solid ${C.border}`,
              color: C.mutedText,
              padding: "4px 10px",
              fontSize: 9,
              fontFamily: FONT_MONO,
              letterSpacing: "0.15em",
              cursor: "pointer",
            }}
          >
            SIGN OUT
          </button>
        </div>
      </div>

      {/* ── CRYPTO INFO STRIP ── */}
      {myPubKeyHex && (
        <div style={{
          background: C.bg,
          borderBottom: `1px solid ${C.border}`,
          padding: "6px 16px",
          display: "flex",
          gap: 24,
          flexShrink: 0,
          overflowX: "auto",
        }}>
          {[
            ["MY PUBKEY (P-256)", myPubKeyHex.slice(0, 44) + "…"],
            peerPubKeyHex ? [`${peer.toUpperCase()} PUBKEY`, peerPubKeyHex.slice(0, 44) + "…"] : null,
            ["CIPHER", "AES-256-GCM"],
            ["AUTH", "SHA-256 SALTED"],
          ].filter(Boolean).map(([label, val]) => (
            <div key={label} style={{ flexShrink: 0 }}>
              <div style={{ fontSize: 8, color: C.mutedText, letterSpacing: "0.15em", marginBottom: 2 }}>{label}</div>
              <div style={{
                fontSize: 9,
                color: label === "CIPHER" ? C.green : label === "AUTH" ? C.amber : C.amberDim,
                letterSpacing: "0.04em",
                maxWidth: 220,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}>{val}</div>
            </div>
          ))}
        </div>
      )}

      {/* ── WAITING OVERLAY ── */}
      {!ready && (
        <div style={{
          position: "fixed", inset: 0,
          background: "rgba(6,6,10,0.93)",
          display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center",
          gap: 20, zIndex: 40,
        }}>
          <div style={{
            width: 36, height: 36,
            border: `2px solid ${C.border}`,
            borderTopColor: C.amber,
            borderRadius: "50%",
            animation: "spin 0.9s linear infinite",
          }} />
          <div style={{ fontFamily: FONT_TITLE, fontSize: 11, color: C.amber, letterSpacing: "0.2em" }}>
            {status}
          </div>
          <div style={{
            fontSize: 10, color: C.mutedText, maxWidth: 320,
            textAlign: "center", lineHeight: 1.8, letterSpacing: "0.08em",
          }}>
            OPEN A SECOND BROWSER WINDOW · LOG IN AS{" "}
            <span style={{ color: userColor[peer] }}>{peer.toUpperCase()}</span>{" "}
            · ECDH HANDSHAKE WILL COMPLETE AUTOMATICALLY
          </div>
        </div>
      )}

      {/* ── MESSAGE AREA ── */}
      <div style={{
        flex: 1, overflowY: "auto",
        padding: "16px",
        display: "flex", flexDirection: "column", gap: 8,
      }}>
        {/* Channel header */}
        <div style={{
          textAlign: "center", fontSize: 9,
          color: C.mutedText, letterSpacing: "0.18em",
          padding: "8px 0 12px",
          borderBottom: `1px solid ${C.border}`,
          marginBottom: 4,
        }}>
          {ready
            ? `◈  CHANNEL SECURE  ·  ONLY ${username.toUpperCase()} & ${peer.toUpperCase()} CAN DECRYPT  ·  ◈`
            : status}
        </div>

        {messages.map((m, idx) => {
          const isMine = m.from === username;
          const color = userColor[m.from];
          return (
            <div key={m.id} className="msg-in" style={{
              display: "flex",
              flexDirection: "column",
              alignItems: isMine ? "flex-end" : "flex-start",
              gap: 3,
            }}>
              {/* Packet header */}
              <div style={{
                display: "flex", gap: 8, alignItems: "center",
                flexDirection: isMine ? "row-reverse" : "row",
              }}>
                <span style={{ fontSize: 8, color, letterSpacing: "0.18em" }}>
                  {m.from.toUpperCase()}
                </span>
                <span style={{ fontSize: 8, color: C.mutedText }}>
                  {new Date(m.ts).toLocaleTimeString("en-US", { hour12: false })}
                </span>
                <span
                  style={{
                    fontSize: 8, color: C.amberDim,
                    background: "#0C0C12",
                    border: `1px solid ${C.border}`,
                    padding: "1px 5px",
                    letterSpacing: "0.05em",
                    cursor: "pointer",
                  }}
                  title={`IV: ${m.iv}\nCiphertext: ${m.ciphertext}`}
                >
                  IV:{m.iv.slice(0, 8)}
                </span>
              </div>
              {/* Bubble */}
              <div style={{
                background: isMine ? "#111020" : C.bgPanel,
                border: `1px solid ${isMine ? "#2A2050" : C.border}`,
                borderLeft: !isMine ? `3px solid ${color}` : `1px solid #2A2050`,
                borderRight: isMine ? `3px solid ${color}` : `1px solid ${C.border}`,
                padding: "9px 14px",
                fontSize: 13,
                color: "#D8D8E8",
                maxWidth: 520,
                lineHeight: 1.55,
                wordBreak: "break-word",
                letterSpacing: "0.02em",
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
        background: C.bgPanel,
        padding: "10px 14px",
        display: "flex", gap: 10,
        flexShrink: 0,
        alignItems: "center",
      }}>
        {/* Encryption indicator */}
        <div style={{
          fontSize: 8, color: ready ? C.green : C.mutedText,
          letterSpacing: "0.15em", flexShrink: 0,
          writingMode: "initial",
        }}>
          {ready ? "🔒" : "○"}
        </div>

        <input
          type="text"
          placeholder={
            ready
              ? `TRANSMIT TO ${peer.toUpperCase()} [AES-256-GCM]…`
              : "AWAITING PEER CONNECTION…"
          }
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && sendMessage()}
          disabled={!ready}
          style={{
            flex: 1,
            background: C.bgInput,
            border: `1px solid ${ready ? C.borderLit : C.border}`,
            color: C.amber,
            padding: "10px 14px",
            fontSize: 12,
            fontFamily: FONT_MONO,
            letterSpacing: "0.06em",
            outline: "none",
            opacity: ready ? 1 : 0.4,
          }}
        />
        <button
          onClick={sendMessage}
          disabled={!ready}
          style={{
            background: ready ? C.amber : C.amberDim,
            border: "none",
            color: C.bg,
            padding: "10px 18px",
            fontSize: 10,
            fontFamily: FONT_TITLE,
            fontWeight: 700,
            letterSpacing: "0.2em",
            cursor: ready ? "pointer" : "not-allowed",
            flexShrink: 0,
            transition: "background 0.15s",
          }}
        >
          SEND →
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
