import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { login } from "../services/api";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await login(email, password);
      localStorage.setItem("aiidps_token", res.data.access_token);
      navigate("/dashboard");
    } catch (err) {
      setError(
        err.response?.data?.detail || "Login failed. Check your credentials."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <form style={styles.card} onSubmit={handleSubmit}>
        <h1 style={styles.title}>AI-IDPS</h1>
        <p style={styles.subtitle}>Intrusion Detection & Prevention System</p>

        <label style={styles.label}>Email</label>
        <input
          style={styles.input}
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />

        <label style={styles.label}>Password</label>
        <input
          style={styles.input}
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />

        {error && <p style={styles.error}>{error}</p>}

        <button style={styles.button} type="submit" disabled={loading}>
          {loading ? "Logging in..." : "Login"}
        </button>
      </form>
    </div>
  );
}

const styles = {
  container: {
    minHeight: "100vh",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    backgroundColor: "#0d1117",
    fontFamily: "Segoe UI, sans-serif",
  },
  card: {
    backgroundColor: "#161b22",
    padding: "2.5rem",
    borderRadius: "12px",
    width: "320px",
    boxShadow: "0 0 20px rgba(0,255,150,0.08)",
  },
  title: { color: "#00ff9d", fontSize: "1.8rem", margin: 0, textAlign: "center" },
  subtitle: { color: "#8b949e", fontSize: "0.85rem", textAlign: "center", marginBottom: "1.5rem" },
  label: { color: "#c9d1d9", fontSize: "0.85rem", display: "block", marginTop: "1rem" },
  input: {
    width: "100%", padding: "0.6rem", marginTop: "0.3rem", borderRadius: "6px",
    border: "1px solid #30363d", backgroundColor: "#0d1117", color: "#fff", boxSizing: "border-box",
  },
  button: {
    width: "100%", marginTop: "1.5rem", padding: "0.7rem", borderRadius: "6px",
    border: "none", backgroundColor: "#00ff9d", color: "#0d1117", fontWeight: "bold", cursor: "pointer",
  },
  error: { color: "#ff4d4f", fontSize: "0.85rem", marginTop: "0.8rem" },
};