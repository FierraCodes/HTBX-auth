import mongoose from 'mongoose';

const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://fierra:zIQ0krX44C2B0ElT@hitbox.ofl8kib.mongodb.net';
mongoose.connect(MONGO_URI);

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  uuid: { type: [String], default: [] },
}, { collection: 'users' });

const tokenSchema = new mongoose.Schema({
  uuid: { type: String, required: true },
  token: { type: String, required: true },
  created_at: { type: Date, default: Date.now },
}, { collection: 'tokens' });

export const User = mongoose.model('User', userSchema);
export const Token = mongoose.model('Token', tokenSchema);
