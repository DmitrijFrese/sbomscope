import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

import { App } from './App';
import { SbomProvider } from './sboms/SbomProvider';
import { ThemeProvider } from './theme/ThemeProvider';
import './styles/app.css';

const container = document.getElementById('root');
if (!container) {
  throw new Error('Cannot start SBOMscope: #root element is missing from index.html');
}

createRoot(container).render(
  <StrictMode>
    <ThemeProvider>
      <SbomProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </SbomProvider>
    </ThemeProvider>
  </StrictMode>,
);
