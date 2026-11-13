/**
 * Server-Sent Events (SSE) hub broadcasting real-time sync sequence numbers
 * across connected Web, Android, and iOS devices without leaking plaintext.
 */

export interface SyncBroadcastEvent {
  type: 'sync_cursor';
  latestSyncSeq: number;
  itemType: string;
  timestamp: string;
}

type SseListener = (event: SyncBroadcastEvent) => void;

export class SyncSseHub {
  private readonly listeners = new Set<SseListener>();

  subscribe(listener: SseListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  broadcast(latestSyncSeq: number, itemType: string): void {
    if (this.listeners.size === 0) return;
    const payload: SyncBroadcastEvent = {
      type: 'sync_cursor',
      latestSyncSeq,
      itemType,
      timestamp: new Date().toISOString(),
    };
    for (const listener of this.listeners) {
      try {
        listener(payload);
      } catch {
        // ignore disconnected stream
      }
    }
  }

  get activeSubscriberCount(): number {
    return this.listeners.size;
  }
}
