// Learn more https://docs.expo.dev/guides/monorepos
const { getDefaultConfig } = require('expo/metro-config');

/** @type {import('expo/metro-config').MetroConfig} */
const config = getDefaultConfig(__dirname);

config.resolver.alias = {
  crypto: 'react-native-crypto-js',
  stream: 'stream-browserify',
  buffer: '@craftzdog/react-native-buffer',
};

module.exports = config;