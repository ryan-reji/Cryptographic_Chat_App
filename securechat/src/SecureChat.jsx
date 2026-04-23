// CryptChat.jsx — End-to-End Encrypted Chat with ECDH + AES-GCM + SHA-256
import { useState, useEffect, useRef } from "react";
import { initializeApp } from "firebase/app";
import { getDatabase, ref, push, onValue, set, get } from "firebase/database";
 
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
 
const USERS = { divine: "alice_password_123", marshal: "bob_password_456" };
 
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
  return (await hashPassword(password, saltHex)) === storedHash;
}
async function generateECDHKeypair() {
  return crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]);
}
async function exportPublicKey(keypair) {
  const raw = await crypto.subtle.exportKey("raw", keypair.publicKey);
  return bytesToHex(new Uint8Array(raw));
}
async function deriveSharedAESKey(privateKey, peerPublicKeyHex) {
  const peerPublicKey = await crypto.subtle.importKey("raw", hexToBytes(peerPublicKeyHex), { name: "ECDH", namedCurve: "P-256" }, false, []);
  return crypto.subtle.deriveKey({ name: "ECDH", public: peerPublicKey }, privateKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptMessage(text, aesKey) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, new TextEncoder().encode(text));
  return { iv: bytesToHex(iv), ciphertext: bytesToHex(new Uint8Array(ciphertext)) };
}
async function decryptMessage(ivHex, ciphertextHex, aesKey) {
  try {
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(ivHex) }, aesKey, hexToBytes(ciphertextHex));
    return new TextDecoder().decode(plaintext);
  } catch { return "[DECRYPTION FAILED]"; }
}
function bytesToHex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(""); }
function hexToBytes(hex) { const a = new Uint8Array(hex.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(hex.slice(i*2,i*2+2),16); return a; }
function randomHex(bytes = 16) { return bytesToHex(crypto.getRandomValues(new Uint8Array(bytes))); }
 
const DB_NAME = "SecureChatStore", STORE_NAME = "KeyPairs";
async function saveKeyLocally(username, keypair) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => { if (!req.result.objectStoreNames.contains(STORE_NAME)) req.result.createObjectStore(STORE_NAME); };
    req.onsuccess = () => { const tx = req.result.transaction(STORE_NAME, "readwrite"); tx.objectStore(STORE_NAME).put(keypair, username); tx.oncomplete = resolve; };
    req.onerror = () => reject(req.error);
  });
}
async function getLocalKey(username) {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === "undefined") return resolve(null);
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => { if (!req.result.objectStoreNames.contains(STORE_NAME)) req.result.createObjectStore(STORE_NAME); };
    req.onsuccess = () => { const gr = req.result.transaction(STORE_NAME,"readonly").objectStore(STORE_NAME).get(username); gr.onsuccess = () => resolve(gr.result); };
    req.onerror = () => reject(req.error);
  });
}
 
const GLOBAL_CSS = `
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
:root{
  --np:#FF2D78;--nc:#00F5FF;--npu:#BF00FF;--nl:#AAFF00;
  --dark:#060410;--dark2:#0D0820;--dark3:#130B2B;
  --glass:rgba(255,255,255,0.04);--gb:rgba(255,255,255,0.12);--gs:rgba(255,255,255,0.08);
}
@keyframes float{0%,100%{transform:translateY(0) rotate(0)}33%{transform:translateY(-18px) rotate(2deg)}66%{transform:translateY(-8px) rotate(-1deg)}}
@keyframes spin-slow{to{transform:rotate(360deg)}}
@keyframes spin-rev{to{transform:rotate(-360deg)}}
@keyframes pulse-ring{0%{transform:scale(.95);opacity:1}70%{transform:scale(1.4);opacity:0}100%{transform:scale(.95);opacity:0}}
@keyframes glitch-1{0%,100%{clip-path:inset(0 0 100% 0);transform:translate(0)}10%{clip-path:inset(15% 0 60% 0);transform:translate(-4px,0)}20%{clip-path:inset(40% 0 30% 0);transform:translate(4px,0)}30%{clip-path:inset(70% 0 5% 0);transform:translate(-2px,0)}40%{clip-path:inset(0 0 100% 0)}}
@keyframes glitch-2{0%,100%{clip-path:inset(0 0 100% 0);transform:translate(0)}15%{clip-path:inset(60% 0 20% 0);transform:translate(4px,0)}35%{clip-path:inset(10% 0 70% 0);transform:translate(-4px,0)}45%{clip-path:inset(0 0 100% 0)}}
@keyframes marquee{from{transform:translateX(0)}to{transform:translateX(-50%)}}
@keyframes fadeSlideUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
@keyframes scanline-move{0%{transform:translateY(-100%)}100%{transform:translateY(100vh)}}
@keyframes grid-pulse{0%,100%{opacity:.3}50%{opacity:.6}}
@keyframes orb-1{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(80px,-60px) scale(1.2)}66%{transform:translate(-40px,80px) scale(.9)}}
@keyframes orb-2{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(-70px,50px) scale(.8)}66%{transform:translate(60px,-80px) scale(1.3)}}
@keyframes orb-3{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(50px,50px) scale(1.1)}}
.cc-bg{background:var(--dark);min-height:100vh;position:relative;overflow:hidden;font-family:'Space Grotesk',sans-serif;}
.cc-grid{position:fixed;inset:0;pointer-events:none;z-index:0;background-image:linear-gradient(rgba(0,245,255,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(0,245,255,.06) 1px,transparent 1px);background-size:48px 48px;animation:grid-pulse 4s ease infinite;}
.cc-scanline{position:fixed;left:0;right:0;height:120px;pointer-events:none;z-index:2;background:linear-gradient(transparent,rgba(0,245,255,.03),transparent);animation:scanline-move 6s linear infinite;}
.cc-orb{position:fixed;border-radius:50%;filter:blur(80px);pointer-events:none;z-index:0;}
.glass-card{background:var(--glass);border:1px solid var(--gb);backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);}
.neon-text-cyan{color:var(--nc);text-shadow:0 0 20px rgba(0,245,255,.6);}
.glitch-title{position:relative;}
.glitch-title::before{content:attr(data-text);position:absolute;inset:0;color:var(--nc);animation:glitch-1 5s infinite;opacity:.7;}
.glitch-title::after{content:attr(data-text);position:absolute;inset:0;color:var(--np);animation:glitch-2 5s infinite .1s;opacity:.7;}
.cc-input{width:100%;background:rgba(0,0,0,.3);border:1px solid var(--gb);border-radius:10px;color:#fff;padding:11px 14px;font-size:14px;font-family:'Space Grotesk',sans-serif;outline:none;transition:border-color .2s,box-shadow .2s;}
.cc-input:focus{border-color:var(--nc);box-shadow:0 0 0 3px rgba(0,245,255,.15),inset 0 0 20px rgba(0,245,255,.05);}
.cc-input::placeholder{color:rgba(255,255,255,.25);}
select.cc-input{appearance:none;cursor:pointer;}
select.cc-input option{background:#130B2B;color:white;}
.cc-btn-primary{width:100%;background:linear-gradient(135deg,var(--np),var(--npu));border:none;border-radius:10px;color:white;padding:12px 0;font-size:14px;font-family:'Space Grotesk',sans-serif;font-weight:600;cursor:pointer;letter-spacing:.04em;position:relative;overflow:hidden;transition:transform .1s,opacity .15s;}
.cc-btn-primary::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.2),transparent);opacity:0;transition:opacity .2s;}
.cc-btn-primary:hover::before{opacity:1;}
.cc-btn-primary:active{transform:scale(.98);}
.cc-btn-primary:disabled{opacity:.4;cursor:not-allowed;}
.cc-send-btn{background:linear-gradient(135deg,var(--nc),#0066FF);border:none;border-radius:10px;color:#000;padding:0 22px;height:44px;font-size:13px;font-family:'Space Grotesk',sans-serif;font-weight:700;cursor:pointer;white-space:nowrap;transition:transform .1s,opacity .15s;flex-shrink:0;}
.cc-send-btn:hover{opacity:.9;}
.cc-send-btn:active{transform:scale(.97);}
.cc-send-btn:disabled{opacity:.3;cursor:not-allowed;}
.cc-msg{animation:fadeSlideUp .2s ease both;}
.ticker-wrap{overflow:hidden;white-space:nowrap;border-top:1px solid rgba(0,245,255,.15);border-bottom:1px solid rgba(0,245,255,.15);background:rgba(0,245,255,.04);padding:6px 0;}
.ticker-inner{display:inline-block;animation:marquee 20s linear infinite;}
::-webkit-scrollbar{width:4px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:rgba(0,245,255,.3);border-radius:4px;}
.signout-pill{background:rgba(255,255,255,.07);border:1px solid var(--gb);color:rgba(255,255,255,.6);padding:5px 14px;border-radius:20px;font-size:12px;font-family:'Space Grotesk',sans-serif;cursor:pointer;transition:background .15s,color .15s;}
.signout-pill:hover{background:rgba(255,45,120,.15);color:var(--np);border-color:var(--np);}
.secure-badge{display:inline-flex;align-items:center;gap:6px;background:rgba(170,255,0,.08);border:1px solid rgba(170,255,0,.3);border-radius:20px;padding:4px 12px;font-size:11px;color:var(--nl);font-weight:600;letter-spacing:.05em;}
.secure-dot{width:6px;height:6px;border-radius:50%;background:var(--nl);box-shadow:0 0 8px var(--nl);animation:pulse-ring 2s ease infinite;}
.crypto-chip{display:inline-flex;align-items:center;gap:6px;background:rgba(191,0,255,.08);border:1px solid rgba(191,0,255,.25);border-radius:6px;padding:3px 10px;font-size:10px;font-family:'Space Mono',monospace;color:rgba(191,0,255,.9);flex-shrink:0;}
.user-tag-divine{background:rgba(255,45,120,.12);border:1px solid rgba(255,45,120,.3);color:var(--np);border-radius:20px;padding:3px 12px;font-size:12px;font-weight:600;}
.user-tag-marshal{background:rgba(0,245,255,.1);border:1px solid rgba(0,245,255,.3);color:var(--nc);border-radius:20px;padding:3px 12px;font-size:12px;font-weight:600;}
`;
 
function BgEffects() {
  return (
    <>
      <style>{GLOBAL_CSS}</style>
      <div className="cc-grid" />
      <div className="cc-scanline" />
      <div className="cc-orb" style={{ width:500,height:500,background:"rgba(191,0,255,.15)",top:"-200px",left:"-100px",animation:"orb-1 12s ease infinite" }} />
      <div className="cc-orb" style={{ width:400,height:400,background:"rgba(255,45,120,.12)",bottom:"-150px",right:"-100px",animation:"orb-2 15s ease infinite" }} />
      <div className="cc-orb" style={{ width:300,height:300,background:"rgba(0,245,255,.08)",top:"40%",left:"60%",animation:"orb-3 10s ease infinite" }} />
    </>
  );
}
 
function LoginScreen({ onLogin }) {
  const [user, setUser] = useState("divine");
  const [pass, setPass] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
 
  async function handleLogin() {
    setLoading(true); setError("");
    try {
      const correctPass = USERS[user];
      if (!correctPass) { setError("Unknown operator ID."); setLoading(false); return; }
      const userRef = ref(db, `users/${user}`);
      const snap = await get(userRef);
      if (!snap.exists()) {
        const salt = randomHex(16);
        await set(userRef, { salt, hash: await hashPassword(correctPass, salt) });
        onLogin(user);
      } else {
        const { salt, hash } = snap.val();
        if (await verifyPassword(pass, salt, hash)) onLogin(user);
        else setError("Wrong passphrase — access denied.");
      }
    } catch (e) { setError("System error: " + e.message); }
    setLoading(false);
  }
 
  return (
    <div className="cc-bg" style={{ display:"flex",alignItems:"center",justifyContent:"center" }}>
      <BgEffects />
      <div style={{ position:"absolute",width:600,height:600,borderRadius:"50%",border:"1px dashed rgba(0,245,255,.1)",animation:"spin-slow 30s linear infinite",pointerEvents:"none" }} />
      <div style={{ position:"absolute",width:400,height:400,borderRadius:"50%",border:"1px dashed rgba(255,45,120,.1)",animation:"spin-rev 20s linear infinite",pointerEvents:"none" }} />
 
      <div className="glass-card" style={{ width:380,borderRadius:20,overflow:"hidden",position:"relative",zIndex:10 }}>
        <div style={{ height:3,background:"linear-gradient(90deg,#FF2D78,#BF00FF,#00F5FF,#AAFF00,#FF2D78)",backgroundSize:"200% 100%",animation:"marquee 3s linear infinite" }} />
        <div style={{ padding:"32px 28px 36px" }}>
          <div style={{ marginBottom:32,textAlign:"center" }}>
            <div style={{ marginBottom:8,position:"relative",display:"inline-block" }}>
              <div className="glitch-title" data-text="CRYPTCHAT" style={{ fontFamily:"'Space Mono',monospace",fontSize:36,fontWeight:700,color:"white",letterSpacing:".08em",position:"relative",zIndex:1 }}>
                CRYPTCHAT
              </div>
            </div>
            <div style={{ display:"flex",justifyContent:"center",gap:6,flexWrap:"wrap" }}>
              {["ECDH P-256","AES-256-GCM","SHA-256"].map(t => <span key={t} className="crypto-chip">{t}</span>)}
            </div>
          </div>
 
          {error && (
            <div style={{ background:"rgba(255,45,120,.1)",border:"1px solid rgba(255,45,120,.4)",borderRadius:8,padding:"10px 14px",fontSize:13,color:"#FF8FAD",marginBottom:20,lineHeight:1.5 }}>
              ⚠ {error}
            </div>
          )}
 
          <div style={{ marginBottom:14 }}>
            <label style={{ display:"block",fontSize:11,fontWeight:600,color:"rgba(255,255,255,.4)",letterSpacing:".12em",textTransform:"uppercase",marginBottom:6 }}>Operator ID</label>
            <select className="cc-input" value={user} onChange={e => setUser(e.target.value)}>
              <option value="divine">DIVINE</option>
              <option value="marshal">MARSHAL</option>
            </select>
          </div>
 
          <div style={{ marginBottom:24 }}>
            <label style={{ display:"block",fontSize:11,fontWeight:600,color:"rgba(255,255,255,.4)",letterSpacing:".12em",textTransform:"uppercase",marginBottom:6 }}>Passphrase</label>
            <input type="password" placeholder="Enter clearance code…" value={pass} onChange={e => setPass(e.target.value)} onKeyDown={e => e.key === "Enter" && handleLogin()} className="cc-input" />
          </div>
 
          <button onClick={handleLogin} disabled={loading} className="cc-btn-primary">
            {loading ? "AUTHENTICATING…" : "INITIATE SECURE SESSION →"}
          </button>
 
          <div style={{ marginTop:24,paddingTop:20,borderTop:"1px solid rgba(255,255,255,.08)",display:"grid",gridTemplateColumns:"1fr 1fr",gap:"10px 16px" }}>
            {[["Auth","SHA-256 salted"],["Key exchange","ECDH P-256"],["Cipher","AES-256-GCM"],["IV size","96-bit random"]].map(([k,v]) => (
              <div key={k}>
                <div style={{ fontSize:10,color:"rgba(255,255,255,.3)",marginBottom:2 }}>{k}</div>
                <div style={{ fontSize:11,fontFamily:"'Space Mono',monospace",color:"rgba(0,245,255,.7)" }}>{v}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
 
function ChatScreen({ username, onLogout }) {
  const peer = username === "divine" ? "marshal" : "divine";
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
 
  useEffect(() => { const t = setInterval(() => setTime(new Date()), 1000); return () => clearInterval(t); }, []);
 
  useEffect(() => {
    (async () => {
      setStatus("Checking local key store…");
      let kp = await getLocalKey(username);
      if (!kp) { setStatus("Generating ECDH keypair…"); kp = await generateECDHKeypair(); await saveKeyLocally(username, kp); }
      keypairRef.current = kp;
      const pubHex = await exportPublicKey(kp);
      setMyPubKeyHex(pubHex);
      await set(ref(db, `keys/${username}`), { pubKey: pubHex, ts: Date.now() });
      setStatus(`Awaiting peer [${peer.toUpperCase()}]…`);
      const unsub = onValue(ref(db, `keys/${peer}`), async snap => {
        if (!snap.exists()) return;
        const { pubKey } = snap.val();
        setPeerPubKeyHex(pubKey);
        setStatus("Deriving shared AES key…");
        try { aesKeyRef.current = await deriveSharedAESKey(kp.privateKey, pubKey); setStatus("Secure channel established"); setReady(true); }
        catch (e) { setStatus("Key exchange failed: " + e.message); }
      });
      return () => unsub();
    })();
  }, [username, peer]);
 
  useEffect(() => {
    const unsub = onValue(ref(db, "messages"), async snap => {
      if (!snap.exists() || !aesKeyRef.current) return;
      const arr = Object.entries(snap.val()).map(([id,m]) => ({id,...m})).sort((a,b)=>(a.ts||0)-(b.ts||0));
      setMessages(await Promise.all(arr.map(async m => ({ ...m, text: await decryptMessage(m.iv, m.ciphertext, aesKeyRef.current) }))));
    });
    return () => unsub();
  }, [ready]);
 
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior:"smooth" }); }, [messages]);
 
  async function sendMessage() {
    if (!input.trim() || !aesKeyRef.current) return;
    const text = input.trim(); setInput("");
    const { iv, ciphertext } = await encryptMessage(text, aesKeyRef.current);
    await push(ref(db, "messages"), { from: username, iv, ciphertext, ts: Date.now() });
  }
 
  const uColors = { divine:"var(--np)", marshal:"var(--nc)" };
  const uClass = { divine:"user-tag-divine", marshal:"user-tag-marshal" };
  const bBorder = { divine:"rgba(255,45,120,.4)", marshal:"rgba(0,245,255,.4)" };
  const bBg = { divine:"rgba(255,45,120,.06)", marshal:"rgba(0,245,255,.06)" };
  const tickerTxt = "⬡ CRYPTCHAT · ECDH P-256 · AES-256-GCM · SHA-256 SALTED · END-TO-END ENCRYPTED · NO PLAINTEXT STORED · ";
 
  return (
    <div className="cc-bg" style={{ width:"100vw",height:"100vh",display:"flex",flexDirection:"column",overflow:"hidden" }}>
      <BgEffects />
 
      {!ready && (
        <div style={{ position:"fixed",inset:0,background:"rgba(6,4,16,.88)",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",gap:20,zIndex:50,backdropFilter:"blur(8px)" }}>
          <div style={{ width:60,height:60,position:"relative" }}>
            <div style={{ position:"absolute",inset:0,borderRadius:"50%",border:"2px solid transparent",borderTopColor:"var(--nc)",animation:"spin-slow .8s linear infinite" }} />
            <div style={{ position:"absolute",inset:8,borderRadius:"50%",border:"2px solid transparent",borderTopColor:"var(--np)",animation:"spin-rev 1.2s linear infinite" }} />
          </div>
          <div style={{ fontFamily:"'Space Mono',monospace",fontSize:14,color:"var(--nc)",letterSpacing:".1em" }}>{status}</div>
          <div style={{ fontSize:13,color:"rgba(255,255,255,.4)",maxWidth:300,textAlign:"center",lineHeight:1.7 }}>
            Open another browser window · Log in as{" "}
            <span style={{ color:uColors[peer],fontWeight:600 }}>{peer.toUpperCase()}</span>{" "}
            · ECDH handshake auto-completes
          </div>
        </div>
      )}
 
      {/* Topbar */}
      <div className="glass-card" style={{ padding:"0 20px",height:56,display:"flex",alignItems:"center",justifyContent:"space-between",flexShrink:0,zIndex:10,borderRadius:0,borderLeft:"none",borderRight:"none",borderTop:"none" }}>
        <div style={{ display:"flex",alignItems:"center",gap:14 }}>
          <span style={{ fontFamily:"'Space Mono',monospace",fontSize:16,fontWeight:700,color:"white",letterSpacing:".1em" }}>
            CRYPT<span className="neon-text-cyan">CHAT</span>
          </span>
          <div style={{ width:1,height:20,background:"var(--gb)" }} />
          <div style={{ display:"flex",alignItems:"center",gap:8 }}>
            <span className={uClass[username]}>{username.toUpperCase()}</span>
            <span style={{ color:"rgba(255,255,255,.3)",fontSize:12 }}>→</span>
            <span className={uClass[peer]}>{peer.toUpperCase()}</span>
          </div>
          {ready && <span className="secure-badge"><span className="secure-dot" />E2E SECURE</span>}
        </div>
        <div style={{ display:"flex",alignItems:"center",gap:12 }}>
          <span style={{ fontFamily:"'Space Mono',monospace",fontSize:11,color:"rgba(0,245,255,.5)" }}>{time.toLocaleTimeString("en-US",{hour12:false})}</span>
          <button onClick={onLogout} className="signout-pill">SIGN OUT</button>
        </div>
      </div>
 
      {/* Ticker */}
      <div className="ticker-wrap" style={{ zIndex:10,flexShrink:0 }}>
        <span className="ticker-inner" style={{ fontFamily:"'Space Mono',monospace",fontSize:10,color:"rgba(0,245,255,.5)",letterSpacing:".1em" }}>
          {tickerTxt}{tickerTxt}
        </span>
      </div>
 
      {/* Crypto info strip */}
      {myPubKeyHex && (
        <div style={{ background:"rgba(0,0,0,.3)",borderBottom:"1px solid var(--gb)",padding:"6px 20px",display:"flex",gap:20,flexShrink:0,overflowX:"auto",alignItems:"center",zIndex:10 }}>
          {[
            ["MY PUBKEY (P-256)", myPubKeyHex.slice(0,40)+"…"],
            peerPubKeyHex ? [`${peer.toUpperCase()} PUBKEY`, peerPubKeyHex.slice(0,40)+"…"] : null,
            ["CIPHER","AES-256-GCM"],
            ["AUTH","SHA-256 SALTED"],
          ].filter(Boolean).map(([k,v]) => (
            <div key={k} style={{ flexShrink:0,display:"flex",gap:8,alignItems:"center" }}>
              <span style={{ fontSize:9,color:"rgba(255,255,255,.25)",letterSpacing:".1em",fontFamily:"'Space Mono',monospace" }}>{k}</span>
              <span style={{ fontSize:9,fontFamily:"'Space Mono',monospace",color:k==="CIPHER"?"var(--nl)":k==="AUTH"?"var(--np)":"rgba(0,245,255,.6)" }}>{v}</span>
            </div>
          ))}
        </div>
      )}
 
      {/* Messages */}
      <div style={{ flex:1,overflowY:"auto",padding:"20px",display:"flex",flexDirection:"column",gap:10,zIndex:5 }}>
        <div style={{ textAlign:"center",marginBottom:8 }}>
          <div style={{ display:"inline-block",background:"rgba(191,0,255,.08)",border:"1px solid rgba(191,0,255,.2)",borderRadius:20,padding:"6px 18px" }}>
            <span style={{ fontSize:11,fontFamily:"'Space Mono',monospace",color:"rgba(191,0,255,.7)",letterSpacing:".08em" }}>
              {ready ? `◈ CHANNEL SECURE · ONLY ${username.toUpperCase()} & ${peer.toUpperCase()} CAN DECRYPT ◈` : status}
            </span>
          </div>
        </div>
 
        {messages.map(m => {
          const isMine = m.from === username;
          const col = uColors[m.from];
          return (
            <div key={m.id} className="cc-msg" style={{ display:"flex",flexDirection:"column",alignItems:isMine?"flex-end":"flex-start",gap:4 }}>
              <div style={{ display:"flex",gap:8,alignItems:"center",flexDirection:isMine?"row-reverse":"row" }}>
                <div style={{ width:26,height:26,borderRadius:"50%",background:isMine?"rgba(255,45,120,.15)":"rgba(0,245,255,.1)",border:`1px solid ${col}55`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:11,fontWeight:700,color:col }}>
                  {m.from[0].toUpperCase()}
                </div>
                <span style={{ fontSize:11,color:"rgba(255,255,255,.3)",fontFamily:"'Space Mono',monospace" }}>
                  {new Date(m.ts).toLocaleTimeString("en-US",{hour12:false})}
                </span>
                <span title={`IV: ${m.iv}\nCiphertext: ${m.ciphertext}`} style={{ fontSize:9,color:"rgba(255,255,255,.2)",background:"rgba(255,255,255,.04)",border:"1px solid rgba(255,255,255,.08)",borderRadius:4,padding:"1px 6px",fontFamily:"'Space Mono',monospace",cursor:"default" }}>
                  IV:{m.iv.slice(0,8)}
                </span>
              </div>
              <div style={{ background:bBg[m.from],border:`1px solid ${bBorder[m.from]}`,borderLeft:!isMine?`3px solid ${col}`:undefined,borderRight:isMine?`3px solid ${col}`:undefined,borderRadius:12,padding:"10px 16px",fontSize:14,color:"rgba(255,255,255,.9)",maxWidth:520,lineHeight:1.6,wordBreak:"break-word" }}>
                {m.text}
              </div>
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>
 
      {/* Input */}
      <div className="glass-card" style={{ padding:"12px 18px",display:"flex",gap:10,flexShrink:0,alignItems:"center",zIndex:10,borderRadius:0,borderLeft:"none",borderRight:"none",borderBottom:"none" }}>
        <div style={{ flexShrink:0,width:16,height:16 }}>
          {ready ? (
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <rect x="2" y="7" width="12" height="8" rx="2" fill="rgba(170,255,0,.15)" stroke="#AAFF00" strokeWidth="1.3"/>
              <path d="M5 7V5a3 3 0 016 0v2" stroke="#AAFF00" strokeWidth="1.3" strokeLinecap="round"/>
              <circle cx="8" cy="11" r="1" fill="#AAFF00"/>
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <rect x="2" y="7" width="12" height="8" rx="2" stroke="rgba(255,255,255,.2)" strokeWidth="1.3"/>
              <path d="M5 7V5a3 3 0 016 0v2" stroke="rgba(255,255,255,.2)" strokeWidth="1.3" strokeLinecap="round"/>
            </svg>
          )}
        </div>
        <input type="text" placeholder={ready?`Message ${peer.charAt(0).toUpperCase()+peer.slice(1)} — AES-256-GCM encrypted…`:"Waiting for peer connection…"} value={input} onChange={e=>setInput(e.target.value)} onKeyDown={e=>e.key==="Enter"&&sendMessage()} disabled={!ready} className="cc-input" style={{ flex:1,height:44,borderRadius:10 }} />
        <button onClick={sendMessage} disabled={!ready} className="cc-send-btn">SEND →</button>
      </div>
    </div>
  );
}
 
export default function App() {
  const [username, setUsername] = useState(null);
  function handleLogout() { if (username) set(ref(db, `keys/${username}`), null); setUsername(null); }
  if (!username) return <LoginScreen onLogin={setUsername} />;
  return <ChatScreen username={username} onLogout={handleLogout} />;
}
