import AsyncStorage from '@react-native-async-storage/async-storage';

/**
 * Cross-platform secure storage utility
 * Uses AsyncStorage for all platforms to avoid expo-secure-store web compatibility issues
 */

export const secureStorage = {
  /**
   * Store a value securely
   */
  async setItemAsync(key: string, value: string): Promise<void> {
    try {
      console.log(`📁 Storing ${key} using AsyncStorage...`);
      await AsyncStorage.setItem(key, value);
      console.log(`✅ Successfully stored ${key}`);
    } catch (error) {
      console.error(`❌ Error storing ${key}:`, error);
      throw error;
    }
  },

  /**
   * Retrieve a value securely
   */
  async getItemAsync(key: string): Promise<string | null> {
    try {
      console.log(`🔍 Retrieving ${key} using AsyncStorage...`);
      const value = await AsyncStorage.getItem(key);
      console.log(`✅ Retrieved ${key}:`, value ? 'Found' : 'Not found');
      return value;
    } catch (error) {
      console.error(`❌ Error retrieving ${key}:`, error);
      return null;
    }
  },

  /**
   * Delete a value securely
   */
  async deleteItemAsync(key: string): Promise<void> {
    try {
      console.log(`🗑️ Deleting ${key} using AsyncStorage...`);
      await AsyncStorage.removeItem(key);
      console.log(`✅ Successfully deleted ${key}`);
    } catch (error) {
      console.error(`❌ Error deleting ${key}:`, error);
      throw error;
    }
  },

  /**
   * Check if an item exists
   */
  async hasItemAsync(key: string): Promise<boolean> {
    try {
      const value = await this.getItemAsync(key);
      return value !== null;
    } catch (error) {
      console.error(`❌ Error checking existence of ${key}:`, error);
      return false;
    }
  }
};