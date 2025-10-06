
import { createSession, attachSocket } from '../modules/ws-sessions.js';
import { Token } from '../modules/db.js';
import jwt from 'jsonwebtoken';
import logger from '../modules/logger.js';

const JWT_SECRET = process.env.JWT_SECRET;

export function init(req, res) {
  const uuid = req.query.uuid;
  const token = req.query.token;

  if (!uuid || !token) return res.status(400).json({ error: 'UUID and token required' });

  const sessionToken = createSession(uuid);
  const wsUrl = `ws://${req.headers.host}/checktoken?uuid=${uuid}&token=${sessionToken}&jwt=${token}`;

  logger.info(`Token check session created for UUID ${uuid}`);
  res.json({ wsUrl });
}

export function wsHandler(ws, req) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const uuid = url.searchParams.get('uuid');
  const sessionToken = url.searchParams.get('token');
  const jwtToken = url.searchParams.get('jwt');

  if (!attachSocket(sessionToken, ws, uuid)) {
    logger.error(`❌ Failed to attach checktoken WS for UUID ${uuid}`);
    logger.info('Closing websocket: failed to attach checktoken');
    ws.close();
    return;
  }

  logger.info(`🔍 Token check WS connected for UUID ${uuid}`);

  // Token verification
  (async () => {
    logger.info(`📥 Checktoken processing JWT for ${uuid}`);
    logger.info(`📋 JWT token (first 20 chars): ${jwtToken?.substring(0, 20)}...`);
    
    try {
      const payload = jwt.verify(jwtToken, JWT_SECRET);
      logger.info(`📋 JWT payload verified for user: ${payload.username}`);
      
      const entry = await Token.findOne({ uuid, token: jwtToken });
      if (!entry) {
        logger.info(`📋 Token not found in database for UUID: ${uuid}`);
        ws.send(JSON.stringify({ status: 'error', message: 'Token not found in DB' }));
        logger.info('Closing websocket: token not found in DB');
      } else {
        logger.info(`📤 Checktoken sending success response for ${uuid}`);
        ws.send(JSON.stringify({ status: 'success', message: 'Token valid', username: payload.username }));
        logger.info('Closing websocket: token valid');
      }
    } catch (err) {
      logger.info(`📋 JWT verification failed for ${uuid}: ${err.message}`);
      ws.send(JSON.stringify({ status: 'error', message: 'Invalid or expired token' }));
      logger.info('Closing websocket: invalid or expired token');
    }
    ws.close();
  })();
}
