import { Token } from "./db.js";
import jwt from "jsonwebtoken";

const SECRET = process.env.JWT_SECRET;

export async function storeToken(uuid, token, ttlSeconds = 3600) {
  const expires = new Date(Date.now() + ttlSeconds * 1000);
  await Token.create({ uuid, token, created_at: new Date(), expires_at: expires });
}

export async function getToken(token) {
  return await Token.findOne({ token });
}

export async function getTokensByUUID(uuid) {
  return await Token.find({ uuid });
}

export async function revokeToken(token) {
  await Token.deleteOne({ token });
}

export async function revokeAllTokens(uuid) {
  await Token.deleteMany({ uuid });
}

export async function cleanExpiredTokens() {
  await Token.deleteMany({ expires_at: { $lt: new Date() } });
}

export async function verifyToken(token) {
  try {
    const payload = jwt.verify(token, SECRET);
    const record = await Token.findOne({ token });
    if (!record || record.uuid !== payload.uuid) return null;
    if (record.expires_at && record.expires_at < new Date()) return null;
    return payload;
  } catch (err) {
    return null;
  }
}