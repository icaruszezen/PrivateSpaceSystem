import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.privatespace.mobile',
  appName: 'PSS',
  webDir: 'dist/mobile',
  android: {
    path: 'mobile/android',
    allowMixedContent: true,
    backgroundColor: '#F6F5F0',
  },
  server: {
    androidScheme: 'http',
    cleartext: true,
  },
};

export default config;
