import axios from "axios";

const API_BASE_URL = "http://127.0.0.1:8000";

const api = axios.create({
  baseURL: API_BASE_URL,
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem("aiidps_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const login = (email, password) =>
  api.post("/api/auth/login", { email, password });

export const register = (name, email, password, role = "VIEWER") =>
  api.post("/api/auth/register", { name, email, password, role });

export const getMe = () => api.get("/api/auth/me");

export const getHealth = () => api.get("/health");

export const getDashboardSummary = () => api.get("/api/analytics/summary");
export const getAttackDistribution = () => api.get("/api/analytics/attack-distribution");
export const getSeverityDistribution = () => api.get("/api/analytics/severity-distribution");
export const getDetectionMethods = () => api.get("/api/analytics/detection-methods");
export const getTopSources = () => api.get("/api/analytics/top-sources");

export const getMLModel = () => api.get("/api/ml/model");

export const getAlerts = (params = {}) => api.get("/api/alerts", { params });
export const getBlockedSources = () => api.get("/api/prevention/blocked");
export const getPreventionActions = () => api.get("/api/prevention/actions");

export const generateSimulation = (scenario, count) =>
  api.post("/api/simulation/generate", { scenario, count });
export const runDetection = () => api.post("/api/detection/analyze");

export default api;