import React from 'react';
import ReactDOM from 'react-dom/client';
import PrivateSpaceMobileApp from '../AndroidApp';
import './styles/mobile.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <PrivateSpaceMobileApp />
  </React.StrictMode>,
);
