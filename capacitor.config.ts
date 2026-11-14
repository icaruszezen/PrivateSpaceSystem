import type { CapacitorConfig } from '@capacitor/cli';

const config: CapacitorConfig = {
  appId: 'com.privatespace.mobile',
  appName: 'PrivateSpace',
  webDir: 'dist/mobile',
  android: {
    path: 'mobile/android',
    allowMixedContent: true,
    backgroundColor: '#F8F7F4',
  },
  server: {
    androidScheme: 'http',
    cleartext: true,
  },
};

export default config;
