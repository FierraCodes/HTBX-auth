import { ThemedText } from '@/components/themed-text';
import { ThemedView } from '@/components/themed-view';
import { useAuth } from '@/contexts/AuthContext';
import { useThemeColor } from '@/hooks/use-theme-color';
import React, { useState } from 'react';
import {
    ActivityIndicator,
    KeyboardAvoidingView,
    Platform,
    ScrollView,
    StyleSheet,
    TextInput,
    TouchableOpacity,
} from 'react-native';
import Toast from 'react-native-toast-message';

export default function LoginScreen() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [isRegisterMode, setIsRegisterMode] = useState(false);
  
  const { login, register, isConnecting } = useAuth();
  
  const backgroundColor = useThemeColor({}, 'background');
  const textColor = useThemeColor({}, 'text');
  const iconColor = useThemeColor({}, 'icon');
  const primaryColor = useThemeColor({}, 'tint');

  const handleAuth = async () => {
    if (!username.trim() || !password.trim()) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: 'Please fill in username and password',
      });
      return;
    }

    if (isRegisterMode && !email.trim()) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: 'Please provide an email address',
      });
      return;
    }

    if (password.length < 6) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: 'Password must be at least 6 characters long',
      });
      return;
    }

    try {
      let success = false;
      
      if (isRegisterMode) {
        success = await register(username.trim(), password, email.trim());
        if (success) {
          setIsRegisterMode(false);
          setEmail('');
        }
      } else {
        success = await login(username.trim(), password);
      }
    } catch (error) {
      Toast.show({
        type: 'error',
        text1: 'Error',
        text2: `An error occurred during ${isRegisterMode ? 'registration' : 'login'}`,
      });
    }
  };

  const toggleMode = () => {
    setIsRegisterMode(!isRegisterMode);
    setEmail('');
    setUsername('');
    setPassword('');
  };

  return (
    <KeyboardAvoidingView
      style={[styles.container, { backgroundColor }]}
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
    >
      <ScrollView
        contentContainerStyle={styles.scrollContainer}
        keyboardShouldPersistTaps="handled"
      >
        <ThemedView style={styles.content}>
          <ThemedView style={styles.header}>
            <ThemedText type="title" style={styles.title}>
              {isRegisterMode ? 'Create Account' : 'Welcome Back!'}
            </ThemedText>
            <ThemedText type="subtitle" style={styles.subtitle}>
              {isRegisterMode ? 'Join the community' : 'Sign in to continue'}
            </ThemedText>
            
            <ThemedText style={styles.demoNotice}>
              📱 Demo Mode: Server unreachable, authentication will work offline
            </ThemedText>
          </ThemedView>

          <ThemedView style={styles.form}>
            <ThemedView style={styles.inputContainer}>
              <ThemedText style={styles.label}>Username</ThemedText>
              <TextInput
                style={[
                  styles.input,
                  {
                    borderColor: iconColor || '#ccc',
                    color: textColor,
                    backgroundColor: backgroundColor,
                  },
                ]}
                placeholder="CoolGamer67"
                placeholderTextColor={textColor ? `${textColor}80` : '#999'}
                value={username}
                onChangeText={setUsername}
                autoCapitalize="none"
                keyboardType="default"
                autoComplete="username"
                textContentType="username"
                editable={!isConnecting}
              />
            </ThemedView>

            {isRegisterMode && (
              <ThemedView style={styles.inputContainer}>
                <ThemedText style={styles.label}>Email</ThemedText>
                <TextInput
                  style={[
                    styles.input,
                    {
                      borderColor: iconColor || '#ccc',
                      color: textColor,
                      backgroundColor: backgroundColor,
                    },
                  ]}
                  placeholder="gamer@example.com"
                  placeholderTextColor={textColor ? `${textColor}80` : '#999'}
                  value={email}
                  onChangeText={setEmail}
                  autoCapitalize="none"
                  keyboardType="email-address"
                  autoComplete="email"
                  textContentType="emailAddress"
                  editable={!isConnecting}
                />
              </ThemedView>
            )}

            <ThemedView style={styles.inputContainer}>
              <ThemedText style={styles.label}>Password</ThemedText>
              <TextInput
                style={[
                  styles.input,
                  {
                    borderColor: iconColor || '#ccc',
                    color: textColor,
                    backgroundColor: backgroundColor,
                  },
                ]}
                placeholder="SuperSecretPassword123!"
                placeholderTextColor={textColor ? `${textColor}80` : '#999'}
                value={password}
                onChangeText={setPassword}
                secureTextEntry
                autoComplete="password"
                textContentType="password"
                editable={!isConnecting}
              />
            </ThemedView>

            <TouchableOpacity
              style={[styles.authButton, { backgroundColor: primaryColor }]}
              onPress={handleAuth}
              disabled={isConnecting}
            >
              {isConnecting ? (
                <ActivityIndicator color="white" />
              ) : (
                <ThemedText style={styles.authButtonText}>
                  {isRegisterMode ? 'Create Account' : 'Sign In'}
                </ThemedText>
              )}
            </TouchableOpacity>

            {isConnecting && (
              <ThemedView style={styles.connectingContainer}>
                <ThemedText style={styles.connectingText}>
                  🔐 Establishing secure device-based connection...
                </ThemedText>
              </ThemedView>
            )}

            {!isRegisterMode && (
              <TouchableOpacity style={styles.forgotPassword}>
                <ThemedText type="link" style={styles.forgotPasswordText}>
                  Forgot Password?
                </ThemedText>
              </TouchableOpacity>
            )}
          </ThemedView>

          <ThemedView style={styles.footer}>
            <ThemedText style={styles.footerText}>
              {isRegisterMode ? 'Already have an account?' : "Don't have an account?"}
            </ThemedText>
            <TouchableOpacity onPress={toggleMode} disabled={isConnecting}>
              <ThemedText type="link" style={styles.signUpText}>
                {isRegisterMode ? 'Sign In' : 'Sign Up'}
              </ThemedText>
            </TouchableOpacity>
          </ThemedView>
        </ThemedView>
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
  },
  scrollContainer: {
    flexGrow: 1,
    justifyContent: 'center',
  },
  content: {
    flex: 1,
    paddingHorizontal: 24,
    paddingVertical: 40,
    justifyContent: 'center',
  },
  header: {
    alignItems: 'center',
    marginBottom: 40,
  },
  title: {
    textAlign: 'center',
    marginBottom: 8,
  },
  subtitle: {
    textAlign: 'center',
    opacity: 0.7,
  },
  demoNotice: {
    textAlign: 'center',
    fontSize: 12,
    opacity: 0.6,
    marginTop: 8,
    fontStyle: 'italic',
  },
  form: {
    marginBottom: 40,
  },
  inputContainer: {
    marginBottom: 20,
  },
  label: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 8,
  },
  input: {
    borderWidth: 1,
    borderRadius: 8,
    paddingHorizontal: 16,
    paddingVertical: 12,
    fontSize: 16,
    minHeight: 48,
  },
  authButton: {
    borderRadius: 8,
    paddingVertical: 16,
    alignItems: 'center',
    marginTop: 20,
    minHeight: 48,
    justifyContent: 'center',
  },
  authButtonText: {
    color: 'black',
    fontSize: 16,
    fontWeight: '600',
  },
  connectingContainer: {
    alignItems: 'center',
    marginTop: 16,
    paddingVertical: 8,
  },
  connectingText: {
    fontSize: 14,
    opacity: 0.8,
    textAlign: 'center',
  },
  forgotPassword: {
    alignItems: 'center',
    marginTop: 16,
  },
  forgotPasswordText: {
    fontSize: 14,
  },
  footer: {
    alignItems: 'center',
    gap: 8,
  },
  footerText: {
    fontSize: 14,
    textAlign: 'center',
  },
  signUpText: {
    fontSize: 14,
    fontWeight: '600',
  },
});