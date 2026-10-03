/** LOCKON EWAC — Entry Point */
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './fonts.css';
import './index.css';
import { installCspReporter, cspViolations } from './lib/cspReporter';


/*
  Before React renders, so a violation while the first chunk loads is caught.

  A wrong Content-Security-Policy fails silently: the browser blocks the
  request, the feature stops working, and nothing says why. This turns that into
  a console line naming the directive and the blocked URI.
*/
installCspReporter();

// Reachable from the console and from an automated smoke test, which is the
// only way to ask "did anything get blocked?" after the fact rather than
// needing to have been watching when it happened.
(window as unknown as Record<string, unknown>).__lockonCspViolations = cspViolations;

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
