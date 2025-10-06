import React from 'react';
import { StyleSheet, useColorScheme } from 'react-native';
import { BaseToast, ErrorToast, InfoToast } from 'react-native-toast-message';

// Pre-defined styles for light and dark themes
const lightTheme = {
  backgroundColor: '#ffffff',
  textColor: '#000000',
  tintColor: '#007AFF',
};

const darkTheme = {
  backgroundColor: '#1c1c1e',
  textColor: '#ffffff', 
  tintColor: '#0A84FF',
};

const SuccessToast = (props: any) => {
  // Use useColorScheme directly to avoid hook order issues
  const colorScheme = useColorScheme();
  const theme = colorScheme === 'dark' ? darkTheme : lightTheme;
  
  return (
    <BaseToast
      {...props}
      style={[styles.toast, { borderLeftColor: '#22c55e', backgroundColor: theme.backgroundColor }]}
      contentContainerStyle={styles.contentContainer}
      text1Style={[styles.text1, { color: theme.textColor }]}
      text2Style={[styles.text2, { color: theme.textColor }]}
    />
  );
};

const CustomErrorToast = (props: any) => {
  const colorScheme = useColorScheme();
  const theme = colorScheme === 'dark' ? darkTheme : lightTheme;
  
  return (
    <ErrorToast
      {...props}
      style={[styles.toast, { borderLeftColor: '#ef4444', backgroundColor: theme.backgroundColor }]}
      contentContainerStyle={styles.contentContainer}
      text1Style={[styles.text1, { color: theme.textColor }]}
      text2Style={[styles.text2, { color: theme.textColor }]}
    />
  );
};

const CustomInfoToast = (props: any) => {
  const colorScheme = useColorScheme();
  const theme = colorScheme === 'dark' ? darkTheme : lightTheme;
  
  return (
    <InfoToast
      {...props}
      style={[styles.toast, { borderLeftColor: theme.tintColor, backgroundColor: theme.backgroundColor }]}
      contentContainerStyle={styles.contentContainer}
      text1Style={[styles.text1, { color: theme.textColor }]}
      text2Style={[styles.text2, { color: theme.textColor }]}
    />
  );
};

export const toastConfig = {
  success: SuccessToast,
  error: CustomErrorToast,
  info: CustomInfoToast,
};

const styles = StyleSheet.create({
  toast: {
    borderRadius: 12,
    paddingHorizontal: 16,
    paddingVertical: 12,
    marginHorizontal: 16,
    marginTop: 8,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  contentContainer: {
    paddingHorizontal: 0,
  },
  text1: {
    fontSize: 16,
    fontWeight: '600',
    marginBottom: 4,
  },
  text2: {
    fontSize: 14,
    opacity: 0.8,
  },
});