/** LOCKON EWAC — Error Boundary Component */
import { Component, type ReactNode } from 'react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[LOCKON ErrorBoundary]', error, info.componentStack);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-6 p-8 bg-space-950">
          <div className="w-16 h-16 rounded-2xl bg-risk-critical/10 border border-risk-critical/30 flex items-center justify-center">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-8 h-8 text-risk-critical" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
              <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" />
              <line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
          </div>
          <div className="text-center max-w-md">
            <h2 className="text-xl font-bold text-tactical tracking-wider text-white mb-2">SYSTEM FAULT DETECTED</h2>
            <p className="text-sm text-gray-400 mb-4">An unrecoverable error occurred in the rendering pipeline.</p>
            <code className="block text-xs font-mono text-risk-critical bg-space-900 border border-space-500/20 rounded p-3 mb-6 text-left max-h-32 overflow-y-auto">
              {this.state.error?.message || 'Unknown error'}
            </code>
            <button
              onClick={() => {
                this.setState({ hasError: false, error: null });
                window.location.hash = '/';
                window.location.reload();
              }}
              className="px-6 py-2.5 bg-neon-500/20 text-neon-400 border border-neon-500 rounded-lg text-xs font-tactical tracking-widest hover:bg-neon-500 hover:text-space-950 transition-all"
            >
              REINITIALIZE SYSTEM
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
