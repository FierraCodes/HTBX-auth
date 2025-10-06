"use client";

import { useEffect, useState, useRef } from "react";
import { SecureAuth } from "../modules/auth.js";
import QRCode from 'qrcode';

const uuid = typeof window !== "undefined" ? window.crypto.randomUUID() : "";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const lastMessageTypeRef = useRef("");
  const [connected, setConnected] = useState(false);
  const [loginUser, setLoginUser] = useState("");
  const [status, setStatus] = useState(null);
  const [qrSrc, setQrSrc] = useState(null);
  const [qrValue, setQrValue] = useState(null);
  const authRef = useRef(null);

  useEffect(() => {
    const auth = new SecureAuth("http://localhost:3001");
    authRef.current = auth;

    auth.connectForLogin(
      uuid,
      (decrypted) => {
        if (decrypted.type === "success") {
          setLoginUser(decrypted.username || username);
          setStatus(`✅ Login successful: ${decrypted.message}`);
          setConnected(false);
        } else if (decrypted.type === "error") {
          setStatus(`❗ Error: ${decrypted.message}`);
          setConnected(false);
        }
      },
      (err) => {
        setStatus("🚨 Server error");
        lastMessageTypeRef.current = decrypted.type;
      }
    );

    // Fetch the websocket URL (token) and create a QR image for it
    (async () => {
      try {
        const wsUrl = await auth.fetchLoginWsUrl(uuid);
        const dataUrl = await QRCode.toDataURL(wsUrl, { margin: 2, width: 240 });
        setQrSrc(dataUrl);
        setQrValue(wsUrl);
      } catch (e) {
        console.warn('Could not fetch wsUrl for QR', e);
      }
    })();

    // Poll for shared secret and enable button only when ready
    const poll = setInterval(() => {
      if (auth.sharedSecret) {
        setConnected(true);
        setStatus("Login");
        clearInterval(poll);
      }
    }, 100);
    // Cleanup
    return () => {
      clearInterval(poll);
      auth.close();
    };
  }, []);

  async function submitLogin() {
    if (!authRef.current?.sharedSecret) {
      setStatus("🔒 Shared secret not ready");
      return;
    }
    await authRef.current.submitLogin(uuid, username, password);
    setStatus("📤 Attempting login...");
  }

  return (
    <div style={{
      minHeight: "100vh",
      display: "flex",
      alignItems: "center",
      justifyContent: "center",
      background: "linear-gradient(135deg, #e0e7ff 0%, #f0fdfa 100%)"
    }}>
      <div style={{
        background: "#fff",
        borderRadius: 16,
        boxShadow: "0 4px 24px rgba(0,0,0,0.08)",
        padding: "2.5rem 2rem",
        minWidth: 340,
        maxWidth: 760,
        width: "100%",
        display: 'grid',
        gridTemplateColumns: '1fr 300px',
        gap: 20,
        alignItems: 'start'
      }}>
        <div>
          <h1 style={{
            textAlign: "center",
            fontWeight: 700,
            fontSize: "2rem",
            marginBottom: 24,
            color: "#2563eb"
          }}>🔐 Secure Login</h1>
          <div style={{ marginBottom: 18 }}>
          <label style={{ fontWeight: 500, color: "#374151" }}>Username</label>
          <input
            style={{
              width: "100%",
              padding: "0.5rem",
              borderRadius: 8,
              border: "1px solid #d1d5db",
              marginTop: 4,
              marginBottom: 12,
              fontSize: "1rem"
            }}
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoFocus
          />
          <label style={{ fontWeight: 500, color: "#374151" }}>Password</label>
          <input
            style={{
              width: "100%",
              padding: "0.5rem",
              borderRadius: 8,
              border: "1px solid #d1d5db",
              marginTop: 4,
              marginBottom: 12,
              fontSize: "1rem"
            }}
            placeholder="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button
          onClick={submitLogin}
          disabled={!connected}
          style={{
            width: "100%",
            padding: "0.75rem",
            borderRadius: 8,
            background: connected ? "#2563eb" : "#dbeafe",
            color: connected ? "#fff" : "#6b7280",
            fontWeight: 600,
            fontSize: "1.1rem",
            border: "none",
            boxShadow: connected ? "0 2px 8px rgba(37,99,235,0.08)" : "none",
            cursor: connected ? "pointer" : "not-allowed",
            transition: "background 0.2s"
          }}
        >
          {connected || status !== null ? status : "Connecting..."}
        </button>
          {loginUser && (
            <p style={{ color: "green", fontWeight: "bold", marginTop: 18, textAlign: "center" }}>
              ✅ Logged in successfully as <span>{loginUser}</span>
            </p>
          )}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ width: 240, height: 240, background: '#f8fafc', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 12 }}>
            {qrSrc ? (
              <img src={qrSrc} alt="Login QR" style={{ width: '100%', height: '100%', objectFit: 'contain' }} />
            ) : (
              <div style={{ color: '#9ca3af', textAlign: 'center' }}>QR unavailable</div>
            )}
          </div>
          <div style={{ marginTop: 12, textAlign: 'center', fontSize: 12, color: '#374151' }}>
            {qrValue ? (
              <>
                <div style={{ marginBottom: 6, fontWeight: 600 }}>Scan to login</div>
              </>
            ) : (
              <div style={{ color: '#6b7280' }}>Waiting for token…</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
