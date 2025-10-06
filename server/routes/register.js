import { createSession, attachSocket } from '../modules/ws-sessions.js';
import handleMessage from '../modules/auth.js';
import logger from '../modules/logger.js';

export function init(req, res) {
  const uuid = req.query.uuid;
  if (!uuid) return res.status(400).json({ error: 'UUID required' });

  const token = createSession(uuid);
  const wsUrl = `ws://${req.headers.host}/register?uuid=${uuid}&token=${token}`;
  logger.info(`Register session created for UUID ${uuid}`);

  res.json({ wsUrl });
}

export function wsHandler(ws, req) {
  const url = new URL(req.url, `https://${req.headers.host}`);
  const uuid = url.searchParams.get('uuid');
  const token = url.searchParams.get('token');

  if (!attachSocket(token, ws, uuid)) {
    logger.error(`Failed to attach register WS for UUID ${uuid}`);
    logger.info('Closing websocket: failed to attach register');
    ws.close();
    return;
  }

  logger.info(`📝 Register WS connected for UUID ${uuid}`);

  ws.on('message', async (msg) => {
    const messageStr = msg.toString();
    logger.info(`📥 Register received message from ${uuid}: ${messageStr}`);
    
    try {
      const parsedMessage = JSON.parse(messageStr);
      logger.info(`📋 Parsed message type: ${parsedMessage.type || 'unknown'}`);
    } catch (e) {
      logger.info(`📋 Raw message (not JSON): ${messageStr}`);
    }
    
    const result = await handleMessage(messageStr);
    logger.info(`📤 Register sending response to ${uuid}: ${result}`);
    ws.send(result);
  });

  ws.send(JSON.stringify({ status: 'register-connected' }));
}
