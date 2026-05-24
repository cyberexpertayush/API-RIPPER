import React from 'react';

interface Props {
  children: React.ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends React.Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { error: null };
  }
  
  static getDerivedStateFromError(error: Error): State {
    return { error };
  }
  
  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("ErrorBoundary caught:", error, info);
  }
  
  render() {
    if (this.state.error) {
      return (
        <div style={{
          padding: 20,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: '60vh',
          color: '#ff4d4f',
          fontFamily: 'Inter, sans-serif'
        }}>
          <h2>An error occurred loading this page</h2>
          <p>Check the browser console for details</p>
          <pre style={{ 
            background: '#1c2333', 
            padding: 12, 
            borderRadius: 8,
            maxWidth: 600,
            overflow: 'auto'
          }}>
            {this.state.error.message}
          </pre>
          <button
            onClick={() => window.location.reload()}
            style={{
              marginTop: 16,
              padding: '8px 16px',
              background: '#00e87b',
              border: 'none',
              borderRadius: 4,
              cursor: 'pointer',
              color: '#0d1117'
            }}
          >
            Reload Page
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
