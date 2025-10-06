import { SecureAuth } from '@/lib/SecureAuth';
import { generateDeviceBasedId } from '@/lib/deviceUtils';
import { secureStorage } from '@/lib/secureStorage';
import React, { createContext, ReactNode, useContext, useEffect, useState } from 'react';
import Toast from 'react-native-toast-message';

interface AuthContextType {
  isAuthenticated: boolean;
  token: string | null;
  username: string | null;
  login: (username: string, password: string) => Promise<boolean>;
  register: (username: string, password: string, email?: string) => Promise<boolean>;
  logout: () => Promise<void>;
  isLoading: boolean;
  isConnecting: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

const TOKEN_KEY = 'auth_token';
const USERNAME_KEY = 'username';

interface AuthProviderProps {
  children: ReactNode;
}

const generateDeviceBasedSessionId = async () => {
  try {
    return await generateDeviceBasedId();
  } catch (error) {
    console.error('Failed to generate device-based ID, falling back to random:', error);
    // Fallback UUID
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
};

export function AuthProvider({ children }: AuthProviderProps) {
  const [token, setToken] = useState<string | null>(null);
  const [username, setUsername] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isConnecting, setIsConnecting] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const [storedToken, storedUsername] = await Promise.all([
          secureStorage.getItemAsync(TOKEN_KEY),
          secureStorage.getItemAsync(USERNAME_KEY)
        ]);
        if (storedToken) setToken(storedToken);
        if (storedUsername) setUsername(storedUsername);
      } catch (err) {
        try {
          const s = err instanceof Error ? `${err.name}: ${err.message}` : JSON.stringify(err);
          console.warn('Error loading auth data:', s);
        } catch (_) {
          console.warn('Error loading auth data:', String(err));
        }
      } finally {
        setIsLoading(false);
      }
    })();
  }, []);

  const login = async (user: string, password: string): Promise<boolean> => {
    setIsConnecting(true);
    const uuid = await generateDeviceBasedSessionId();
    const secureAuth = new SecureAuth('http://192.168.100.24:3001');

    try {
      // Attempt to perform the login handshake. Current SecureAuth.connectForLogin returns a token when successful.
      let tokenFromServer: string | null = null;
      try {
        tokenFromServer = await secureAuth.connectForLogin(uuid, user, password);
      } catch (e) {
        // connectForLogin may reject even if it stored a token in secureStorage during the handshake
        // check secureStorage as a fallback
        try {
          const stored = await secureStorage.getItemAsync(TOKEN_KEY);
          if (stored) tokenFromServer = stored;
        } catch (_){/* ignore */}
      }

      if (tokenFromServer) {
        await Promise.all([
          secureStorage.setItemAsync(TOKEN_KEY, tokenFromServer),
          secureStorage.setItemAsync(USERNAME_KEY, user)
        ]);
        setToken(tokenFromServer);
        setUsername(user);
        Toast.show({ type: 'success', text1: 'Welcome back!', text2: `Logged in as ${user}` });
        setIsConnecting(false);
        secureAuth.close();
        return true;
      }

      // If no token, treat as failure
      Toast.show({ type: 'error', text1: 'Login Failed', text2: 'Invalid credentials or server rejected login' });
      setIsConnecting(false);
      secureAuth.close();
      return false;
    } catch (err: any) {
      try {
        const s = err instanceof Error ? `${err.name}: ${err.message}` : JSON.stringify(err);
        console.warn('Login error:', s);
      } catch (_) {
        console.warn('Login error:', String(err));
      }
      secureAuth.close();

      // Demo fallback for network errors
      const msg = err?.message || String(err);
      if (msg.includes('Network request failed')) {
        Toast.show({ type: 'info', text1: 'Demo Mode', text2: 'Server unreachable, using demo authentication' });
        try {
          const demoToken = `demo-token-${Date.now()}`;
          await Promise.all([
            secureStorage.setItemAsync(TOKEN_KEY, demoToken),
            secureStorage.setItemAsync(USERNAME_KEY, user)
          ]);
          setToken(demoToken);
          setUsername(user);
          Toast.show({ type: 'success', text1: 'Demo Login Successful', text2: `Logged in as ${user} (Demo)` });
          setIsConnecting(false);
          return true;
        } catch (e) {
          console.error('Demo login storage failed:', e);
          setIsConnecting(false);
          return false;
        }
      }

      Toast.show({ type: 'error', text1: 'Connection Error', text2: 'Failed to connect to authentication server' });
      setIsConnecting(false);
      return false;
    }
  };

  const register = async (user: string, password: string, email?: string): Promise<boolean> => {
    // For now, reuse the same flow as login since SecureAuth.connectForRegister currently delegates to connectForLogin.
    setIsConnecting(true);
    const uuid = await generateDeviceBasedSessionId();
    const secureAuth = new SecureAuth('http://192.168.100.24:3001');
    try {
      const tokenFromServer = await secureAuth.connectForRegister(uuid);
      if (tokenFromServer) {
        await Promise.all([
          secureStorage.setItemAsync(TOKEN_KEY, tokenFromServer),
          secureStorage.setItemAsync(USERNAME_KEY, user)
        ]);
        setToken(tokenFromServer);
        setUsername(user);
        Toast.show({ type: 'success', text1: 'Registration Successful', text2: `Logged in as ${user}` });
        setIsConnecting(false);
        secureAuth.close();
        return true;
      }
      Toast.show({ type: 'error', text1: 'Registration Failed', text2: 'Server rejected registration' });
      setIsConnecting(false);
      secureAuth.close();
      return false;
    } catch (err: any) {
      try {
        const s = err instanceof Error ? `${err.name}: ${err.message}` : JSON.stringify(err);
        console.warn('Registration error:', s);
      } catch (_) {
        console.warn('Registration error:', String(err));
      }
      secureAuth.close();
      setIsConnecting(false);
      Toast.show({ type: 'error', text1: 'Registration Error', text2: 'Failed to register' });
      return false;
    }
  };

  const logout = async () => {
    try {
      await Promise.all([secureStorage.deleteItemAsync(TOKEN_KEY), secureStorage.deleteItemAsync(USERNAME_KEY)]);
      setToken(null);
      setUsername(null);
      Toast.show({ type: 'success', text1: 'Logged out', text2: 'You have been successfully logged out' });
    } catch (err) {
      try {
        const s = err instanceof Error ? `${err.name}: ${err.message}` : JSON.stringify(err);
        console.warn('Logout error:', s);
      } catch (_) {
        console.warn('Logout error:', String(err));
      }
      Toast.show({ type: 'error', text1: 'Logout Error', text2: 'Failed to clear stored credentials' });
    }
  };

  const value: AuthContextType = {
    isAuthenticated: !!token,
    token,
    username,
    login,
    register,
    logout,
    isLoading,
    isConnecting,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) throw new Error('useAuth must be used within an AuthProvider');
  return context;
}