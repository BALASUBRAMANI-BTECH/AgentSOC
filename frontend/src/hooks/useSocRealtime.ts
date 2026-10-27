import { useEffect, useRef, useState, useCallback } from 'react';
import { SecurityEvent, Incident, ResponseAuditRecord } from '../types/soc';

export type ConnectionStatus = 'connected' | 'connecting' | 'disconnected';

export interface WebSocketMessage {
  type: string;
  event?: SecurityEvent;
  incident?: Incident;
  action?: any;
  [key: string]: any;
}

export function useSocRealtime() {
  const [status, setStatus] = useState<ConnectionStatus>('disconnected');
  const [liveEvents, setLiveEvents] = useState<SecurityEvent[]>([]);
  const [lastIncident, setLastIncident] = useState<Incident | null>(null);
  const [lastResponse, setLastResponse] = useState<any | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<any>(null);

  const connect = useCallback(() => {
    try {
      if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;

      setStatus('connecting');
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      // If dev server port 3000, target 8000
      const host = window.location.port === '3000' ? '127.0.0.1:8000' : window.location.host;
      const wsUrl = `${protocol}//${host}/ws`;

      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setStatus('connected');
      };

      ws.onmessage = (event) => {
        try {
          const data: WebSocketMessage = JSON.parse(event.data);
          if ((data.type === 'EVENT_INGESTED' || data.type === 'NEW_EVENT') && data.event) {
            setLiveEvents((prev) => [data.event!, ...prev.slice(0, 99)]);
          }
          if (data.incident) {
            setLastIncident(data.incident);
          } else if (data.type === 'RESPONSE_EXECUTED' && data.action) {
            setLastResponse(data.action);
          }
        } catch (e) {
          console.error('Failed to parse WS payload', e);
        }
      };

      ws.onclose = () => {
        setStatus('disconnected');
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, 3000);
      };

      ws.onerror = () => {
        setStatus('disconnected');
        ws.close();
      };
    } catch (err) {
      setStatus('disconnected');
      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, 5000);
    }
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) wsRef.current.close();
    };
  }, [connect]);

  return {
    status,
    liveEvents,
    lastIncident,
    lastResponse,
    clearLiveEvents: () => setLiveEvents([]),
  };
}

