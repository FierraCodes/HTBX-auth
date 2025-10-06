import * as Application from 'expo-application';
import * as Crypto from 'expo-crypto';
import * as Device from 'expo-device';

/**
 * Device utilities for generating unique device identifiers
 * Using Expo-compatible APIs only
 */

/**
 * Get device hardware identifier using Expo APIs
 * Uses a combination of device info to create a stable identifier
 */
export const getDeviceIdentifier = async (): Promise<string> => {
  try {
    // Try to get Android ID first (Android only)
    if (Device.osName === 'Android') {
      try {
        const androidId = await Application.getAndroidId();
        if (androidId && androidId !== 'unknown') {
          return androidId;
        }
      } catch (error) {
        console.log('Android ID not available, falling back to device info');
      }
    }

    // For iOS or fallback, use a combination of device info
    const deviceInfo = [
      Device.deviceName || 'unknown',
      Device.modelName || 'unknown', 
      Device.osName || 'unknown',
      Device.osVersion || 'unknown',
      Device.brand || 'unknown',
      Application.nativeApplicationVersion || 'unknown'
    ].join('-');

    return deviceInfo;
  } catch (error) {
    console.error('Error getting device identifier:', error);
    
    // Ultimate fallback - generate a stable ID based on available info
    const fallbackData = [
      Device.osName || 'unknown',
      Device.osVersion || 'unknown', 
      Device.modelName || 'unknown',
      Date.now().toString()
    ].join('-');
    
    return fallbackData;
  }
};

/**
 * Hash a string using SHA-256 with expo-crypto
 */
export const hashString = async (input: string): Promise<string> => {
  try {
    // Use expo-crypto for reliable hashing
    const hashedData = await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      input,
      { encoding: Crypto.CryptoEncoding.HEX }
    );
    
    return hashedData;
  } catch (error) {
    console.error('Error hashing string with expo-crypto:', error);
    
    // Fallback: Simple hash using character codes
    let hash = 0;
    for (let i = 0; i < input.length; i++) {
      const char = input.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash; // Convert to 32bit integer
    }
    
    // Convert to hex and pad to ensure consistent length
    const hexHash = Math.abs(hash).toString(16).padStart(8, '0');
    
    // Extend to SHA-256 length (64 chars) by repeating
    const extendedHash = (hexHash.repeat(8)).substring(0, 64);
    
    return extendedHash;
  }
};

/**
 * Generate a unique device-based identifier
 * This replaces random UUID generation with device hardware-based identification
 */
export const generateDeviceBasedId = async (): Promise<string> => {
  try {
    const deviceId = await getDeviceIdentifier();
    
    // Try to hash the device ID
    try {
      const hashedId = await hashString(deviceId);
      
      // Format as UUID-like string for compatibility
      if (hashedId.length >= 32) {
        const uuid = [
          hashedId.slice(0, 8),
          hashedId.slice(8, 12),
          hashedId.slice(12, 16),
          hashedId.slice(16, 20),
          hashedId.slice(20, 32)
        ].join('-');
        
        return uuid;
      }
    } catch (hashError) {
      console.error('Hashing failed, using device ID directly:', hashError);
    }
    
    // If hashing fails, create UUID from device ID directly
    const safeDeviceId = deviceId.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
    const paddedId = (safeDeviceId + '00000000000000000000000000000000').substring(0, 32);
    
    const uuid = [
      paddedId.slice(0, 8),
      paddedId.slice(8, 12),
      paddedId.slice(12, 16),
      paddedId.slice(16, 20),
      paddedId.slice(20, 32)
    ].join('-');
    
    return uuid;
    
  } catch (error) {
    console.error('Error generating device-based ID:', error);
    
    // Fallback to timestamp-based ID if all else fails
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substr(2, 9);
    return `${timestamp}-${random}-device-fallback`;
  }
};

/**
 * Get device information for debugging
 */
export const getDeviceInfo = async () => {
  try {
    const deviceInfo = {
      deviceName: Device.deviceName,
      osName: Device.osName,
      osVersion: Device.osVersion,
      modelName: Device.modelName,
      brand: Device.brand,
      manufacturer: Device.manufacturer,
      appVersion: Application.nativeApplicationVersion,
      buildVersion: Application.nativeBuildVersion,
    };
    
    return deviceInfo;
  } catch (error) {
    console.error('Error getting device info:', error);
    return null;
  }
};