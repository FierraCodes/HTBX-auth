"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

export default function RegisterPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const router = useRouter();

  async function handleRegister(e) {
    e.preventDefault();
    setLoading(true);
    setError("");
    setSuccess("");
    try {
      const uuid = window.crypto.randomUUID();
      const res = await fetch("https://localhost:3001/register/init?uuid=" + uuid);
      let { wsUrl } = await res.json();
      if (!wsUrl) throw new Error("No wsUrl from server");
      const ws = new window.WebSocket(wsUrl);
      ws.onopen = () => {
        ws.send(
          JSON.stringify({
            type: "register",
            username,
            password,
            uuid,
          })
        );
      };
      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "success") {
            setSuccess("Registration successful!");
            setTimeout(() => router.push("/"), 1200);
          } else {
            setError(data.message || "Registration failed");
          }
        } catch {
          setError("Invalid response from server");
        }
        ws.close();
        setLoading(false);
      };
      ws.onerror = () => {
        setError("WebSocket error");
        setLoading(false);
      };
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  }

  return (
    <div style={{ maxWidth: 400, margin: "40px auto", padding: 24, borderRadius: 12, boxShadow: "0 2px 16px #0001", background: "#fff" }}>
      <h2 style={{ marginBottom: 24 }}>Register</h2>
      <form onSubmit={handleRegister}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={e => setUsername(e.target.value)}
          required
          style={{ width: "100%", marginBottom: 12, padding: 8, borderRadius: 6, border: "1px solid #ccc" }}
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          required
          style={{ width: "100%", marginBottom: 12, padding: 8, borderRadius: 6, border: "1px solid #ccc" }}
        />
        <button
          type="submit"
          disabled={loading}
          style={{ width: "100%", padding: 10, borderRadius: 6, background: "#0070f3", color: "#fff", border: "none", fontWeight: "bold" }}
        >
          {loading ? "Registering..." : "Register"}
        </button>
        {error && <div style={{ color: "#d00", marginTop: 16 }}>{error}</div>}
        {success && <div style={{ color: "#090", marginTop: 16 }}>{success}</div>}
      </form>
    </div>
  );
}
