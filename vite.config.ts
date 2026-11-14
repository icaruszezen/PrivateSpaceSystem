import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';

export default defineConfig({
  root: 'src/client',
  publicDir: '../../public',
  plugins: [
    react(),
    {
      name: 'privatespace-ios-mpa-rewrite',
      configureServer(server) {
        server.middlewares.use((req, _res, next) => {
          if (req.url) {
            const [pathname, search = ''] = req.url.split('?');
            if (pathname === '/ios' || pathname === '/ios/') {
              req.url = `/ios.html${search ? `?${search}` : ''}`;
            }
          }
          next();
        });
      },
    },
  ],
  resolve: {
    alias: {
      '@shared': path.resolve(__dirname, 'src/shared'),
      '@mobile': path.resolve(__dirname, 'mobile'),
      'react-native': path.resolve(__dirname, 'mobile/src/rnWebRuntime.tsx'),
    },
  },
  server: {
    port: 5173,
    fs: {
      allow: [path.resolve(__dirname)],
    },
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
      '/.well-known': {
        target: 'http://127.0.0.1:8080',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: '../../dist/client',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      input: {
        main: path.resolve(__dirname, 'src/client/index.html'),
        ios: path.resolve(__dirname, 'src/client/ios.html'),
      },
    },
  },
});
