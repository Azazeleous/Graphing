import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';
import { initGaiaDriveBridge } from './drivePackageBridge.ts';
import { initDriveSparseMount } from './driveSparseMount.ts';
import { initMerklePowD3Chart } from './merklePowD3Chart.ts';
import { initMemoryStreamD3Panel } from './memoryStreamD3Panel.ts';
import { initGenesis3Evidence } from './genesis3Evidence.ts';
import { initLivingSystemConvergence } from './livingSystemConvergence.ts';

initGaiaDriveBridge();
initDriveSparseMount();
initMerklePowD3Chart();
initMemoryStreamD3Panel();
initGenesis3Evidence();
initLivingSystemConvergence();

const rootEl = document.getElementById('root');
if (rootEl) {
  createRoot(rootEl).render(<App />);
}
