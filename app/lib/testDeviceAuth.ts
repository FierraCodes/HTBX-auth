/**
 * Test script for device-based authentication
 * Run this to verify device ID generation works correctly
 */

import { generateDeviceBasedId, getDeviceIdentifier, getDeviceInfo, hashString } from './deviceUtils';

export const testDeviceAuth = async () => {
  console.log('🔧 Testing Device-Based Authentication...\n');

  try {
    // Test device info
    console.log('📱 Getting device information...');
    const deviceInfo = await getDeviceInfo();
    console.log('Device Info:', JSON.stringify(deviceInfo, null, 2));

    // Test device identifier
    console.log('\n🔑 Getting device identifier...');
    const deviceId = await getDeviceIdentifier();
    console.log('Device ID:', deviceId);

    // Test hashing
    console.log('\n🔐 Testing hash function...');
    const hashedId = await hashString(deviceId);
    console.log('Hashed ID:', hashedId);

    // Test device-based session ID generation
    console.log('\n🆔 Generating device-based session ID...');
    const sessionId1 = await generateDeviceBasedId();
    const sessionId2 = await generateDeviceBasedId();
    
    console.log('Session ID 1:', sessionId1);
    console.log('Session ID 2:', sessionId2);
    
    // Verify consistency
    if (sessionId1 === sessionId2) {
      console.log('✅ Device-based IDs are consistent (good!)');
    } else {
      console.log('❌ Device-based IDs are inconsistent (this might be a problem)');
    }

    // Test multiple generations to ensure stability
    console.log('\n🔄 Testing ID stability with multiple generations...');
    const ids: string[] = [];
    for (let i = 0; i < 5; i++) {
      const id = await generateDeviceBasedId();
      ids.push(id);
    }
    
    const allSame = ids.every(id => id === ids[0]);
    console.log('Generated IDs:', ids);
    console.log(allSame ? '✅ All IDs are identical (stable)' : '❌ IDs are not stable');

    console.log('\n🎉 Device authentication testing complete!');
    
    return {
      deviceInfo,
      deviceId,
      hashedId,
      sessionId: sessionId1,
      isStable: allSame
    };

  } catch (error) {
    console.error('❌ Error during device auth testing:', error);
    throw error;
  }
};

// Export for use in components
export default testDeviceAuth;