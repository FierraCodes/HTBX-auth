import { User, Token } from './db.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import logger from './logger.js';
import {  } from './crypto.js';

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const TTL = process.env.TTL ? parseInt(process.env.TTL, 10) : 3600;

export default function handleMessage(message) {
  let type;
  let msg;
  try {
    msg = JSON.parse(message);
    type = msg.type;
  } catch (err) {
    logger.error(`Invalid JSON format: ${err?.message || err}`);
    return JSON.stringify({ type: 'error', message: 'Invalid JSON format' })
  }
  const { username, password, uuid } = msg;

  if (!username || !password || !uuid) {
    logger.error('Missing username, password, or uuid');
    return JSON.stringify({ type: 'error', message: 'Missing username, password, or uuid' })
  }

  if (type === 'register') {
    return (async () => {
      const existing = await User.findOne({ username });
      if (existing) {
        logger.error(`Username already exists: ${username}`);
        return JSON.stringify({ type: 'error', message: 'Username already exists' });
      }

      const hashed = bcrypt.hashSync(password, 10);
      // Always create with uuid array
      await User.create({ username, password: hashed, uuid: [uuid] });

      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
      await Token.create({ uuid, token, created_at: new Date() });
      return JSON.stringify({ type: 'success', message: 'User registered', token });
    })();
  }

  if (type === 'login') {
    return (async () => {
      logger.info(`Login attempt for username: ${username}`);
      const user = await User.findOne({ username });

      if (!user || !bcrypt.compareSync(password, user.password)) {
        logger.error(`Invalid credentials for username: ${username}`);
        return JSON.stringify({ type: 'error', message: 'Invalid credentials' });
      }

      // Automically update uuid array using findOneAndUpdate
      let uuids = Array.isArray(user.uuid) ? user.uuid : [];
      if (!uuids.includes(uuid)) {
        if (uuids.length >= 3) {
          logger.error(`Binding limit reached for username: ${username}`);
          await User.findOneAndUpdate(
            { username },
            { $set: { uuid: uuids } },
            { new: true }
          );
          return JSON.stringify({ type: 'error', message: 'Exceeded Device Binding Limit' });
        }
        uuids.push(uuid);
      }
      await User.findOneAndUpdate(
        { username },
        { $set: { uuid: uuids } },
        { new: true }
      );

      const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: TTL });
      await Token.create({ uuid, token, created_at: new Date() });
      return JSON.stringify({ type: 'success', message: 'Login successful', token });
    })();
  }

  logger.error(`Unknown message type: ${type}`);
  return JSON.stringify({ type: 'error', message: 'Unknown message type' })
}
