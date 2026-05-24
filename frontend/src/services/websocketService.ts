// Derive WebSocket URL from current page origin (works via Vite proxy)
const API_BASE = ((import.meta as any) && (import.meta as any).env && (import.meta as any).env.VITE_API_BASE)
  ? String((import.meta as any).env.VITE_API_BASE)
  : '/api/v1';

function deriveWsUrl(apiBase: string, wsPath = '/ws') {
  try {
    // If apiBase is a full URL, derive from it
    if (apiBase.startsWith('http')) {
      const u = new URL(apiBase);
      const protocol = u.protocol === 'https:' ? 'wss:' : 'ws:';
      return `${protocol}//${u.host}${wsPath}`;
    }
    // Relative path — derive from current page location (Vite proxy handles it)
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${protocol}//${window.location.host}${wsPath}`;
  } catch (e) {
    return `ws://127.0.0.1:8000/ws`;
  }
}

const WS_PATH = ((import.meta as any).env && (import.meta as any).env.VITE_WS_PATH) ? String((import.meta as any).env.VITE_WS_PATH) : '/ws';
const WS_URL = deriveWsUrl(API_BASE, WS_PATH);

class WebSocketService {
  private ws: WebSocket | null = null;
  private url: string = WS_URL;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectInterval = 3000;
  private wsPath: string = WS_PATH;
  private listeners: { [key: string]: Function[] } = {};

  connect(assessmentId?: string): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        if (assessmentId) {
          this.wsPath = `/ws/scan/${assessmentId}`;
          this.url = deriveWsUrl(API_BASE, this.wsPath);
        }

        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.reconnectAttempts = 0;
          this.emit('connected');
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            this.onMessage(message);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.emit('error', error);
          reject(error);
        };

        this.ws.onclose = () => {
          console.log('WebSocket disconnected');
          this.emit('disconnected');
          this.attemptReconnect();
        };
      } catch (error) {
        reject(error);
      }
    });
  }

  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  send(message: any): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not connected');
    }
  }

  on(event: string, callback: Function): void {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(callback);
  }

  private emit(event: string, data?: any): void {
    if (this.listeners[event]) {
      this.listeners[event].forEach((callback) => callback(data));
    }
  }

  private onMessage(message: any): void {
    const { type, data } = message;
    this.emit(type, data);
    this.emit('message', message);
  }

  private attemptReconnect(): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      console.log(
        `Attempting to reconnect... (${this.reconnectAttempts}/${this.maxReconnectAttempts})`
      );
      setTimeout(() => this.connect().catch(console.error), this.reconnectInterval);
    }
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

export const websocketService = new WebSocketService();
