/** LOCKON EWAC — Root Application Component */
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { lazy, Suspense } from 'react';
import { AppShell } from './components/layout/AppShell';
import { ErrorBoundary } from './components/common/ErrorBoundary';
import { DashboardPage } from './pages/DashboardPage';

/*
  Four of the five screens are loaded on demand.

  Not for bandwidth — this is a desktop application reading from its own install
  directory, and the chunk arrives in a few milliseconds either way. It is for
  the work the engine does before the first frame: every route was in one 2.5 MB
  chunk, so launching to the dashboard parsed and evaluated the whole PDF
  builder, the report section renderers and the credential vault screen before
  anything could be drawn. On a rig that is opened in a vehicle to answer a
  question quickly, that is time spent on screens the operator has not asked for.

  The dashboard stays eager. It is the landing route, so splitting it would move
  work rather than defer it, and it owns the map the operator is usually here to
  look at.

  `ReportsPage` is the one that matters most: it pulls in jsPDF and the autotable
  plugin at module scope, which is the single largest thing in the build after
  MapLibre, and it is reached only when somebody exports.

  The fallback is deliberately plain. A spinner that flashes for 30ms reads as a
  stutter, so this is a quiet panel that says what it is waiting for and would be
  legible if a chunk genuinely failed to arrive.
*/
const IntrusionPage = lazy(() => import('./pages/IntrusionPage').then(m => ({ default: m.IntrusionPage })));
const ReportsPage = lazy(() => import('./pages/ReportsPage').then(m => ({ default: m.ReportsPage })));
const SettingsPage = lazy(() => import('./pages/SettingsPage').then(m => ({ default: m.SettingsPage })));
const DecryptorPage = lazy(() => import('./pages/DecryptorPage').then(m => ({ default: m.DecryptorPage })));

function ScreenLoading() {
  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <span className="text-[10px] font-tactical tracking-widest text-gray-600">LOADING MODULE…</span>
    </div>
  );
}

function App() {
  return (
    <BrowserRouter>
      <ErrorBoundary>
        <Routes>
          <Route element={<AppShell />}>
            <Route path="/" element={<DashboardPage />} />
            {/*
              One boundary per route rather than one around the whole shell: a
              shared boundary would unmount the navigation while a screen loads,
              so the chrome would blink on every move between tabs.
            */}
            <Route path="/intrusion" element={<Suspense fallback={<ScreenLoading />}><IntrusionPage /></Suspense>} />
            <Route path="/decryptor" element={<Suspense fallback={<ScreenLoading />}><DecryptorPage /></Suspense>} />
            <Route path="/reports" element={<Suspense fallback={<ScreenLoading />}><ReportsPage /></Suspense>} />
            <Route path="/settings" element={<Suspense fallback={<ScreenLoading />}><SettingsPage /></Suspense>} />
          </Route>
        </Routes>
      </ErrorBoundary>
    </BrowserRouter>
  );
}

export default App;
