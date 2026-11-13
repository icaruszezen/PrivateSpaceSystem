import { generateTotp, type TotpTokenSnapshot } from '@shared/totp';
import {
  evaluatePasswordEntropy,
  generateSecurePassword,
  type PasswordEntropyReport,
  type PasswordGeneratorOptions,
} from '@shared/passwordGenerator';
import type {
  AuthSessionResponse,
  CreatePasswordRequest,
  MediaAlbum,
  MediaItem,
  NoteItem,
  PasswordItem,
  ResumableUploadInitResponse,
  ResumableUploadStatusResponse,
  SyncPullResponse,
  UpdatePasswordRequest,
} from '@shared/types';

export type MobilePlatform = 'android' | 'ios';

export interface MobileVaultSnapshot {
  lastSyncSeq: number;
  syncedAt: string | null;
  notes: Record<string, NoteItem>;
  passwords: Record<string, PasswordItem>;
  media: Record<string, MediaItem>;
  albums: Record<string, MediaAlbum>;
}

export interface VaultPersistenceAdapter {
  loadSnapshot(): Promise<MobileVaultSnapshot | null>;
  saveSnapshot(snapshot: MobileVaultSnapshot): Promise<void>;
  loadSessionToken(): Promise<string | null>;
  saveSessionToken(token: string | null): Promise<void>;
}

export class InMemoryVaultPersistence implements VaultPersistenceAdapter {
  private snapshot: MobileVaultSnapshot | null = null;
  private token: string | null = null;

  async loadSnapshot(): Promise<MobileVaultSnapshot | null> {
    return this.snapshot ? structuredClone(this.snapshot) : null;
  }

  async saveSnapshot(snapshot: MobileVaultSnapshot): Promise<void> {
    this.snapshot = structuredClone(snapshot);
  }

  async loadSessionToken(): Promise<string | null> {
    return this.token;
  }

  async saveSessionToken(token: string | null): Promise<void> {
    this.token = token;
  }
}

export interface MobileClientOptions {
  baseUrl: string;
  platform: MobilePlatform;
  deviceName: string;
  persistence?: VaultPersistenceAdapter;
  fetchImpl?: typeof fetch;
}

/**
 * Cross-platform Sync & Encrypted Media SDK for PrivateSpace Android & iOS clients.
 * Supports Bearer session tokens, monotonic cursor delta sync (`since_seq`),
 * offline-capable RFC 6238 TOTP generation, resumable chunked video/image uploads,
 * and authenticated HTTP 206 Range URLs for iOS AVPlayer & Android Media3 ExoPlayer.
 */
export class PrivateSpaceMobileClient {
  private readonly baseUrl: string;
  private readonly platform: MobilePlatform;
  private readonly deviceName: string;
  private readonly persistence: VaultPersistenceAdapter;
  private readonly fetchFn: typeof fetch;
  private token: string | null = null;

  constructor(options: MobileClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.platform = options.platform;
    this.deviceName = options.deviceName;
    this.persistence = options.persistence ?? new InMemoryVaultPersistence();
    this.fetchFn = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  }

  async restoreSession(): Promise<string | null> {
    this.token = await this.persistence.loadSessionToken();
    return this.token;
  }

  getToken(): string | null {
    return this.token;
  }

  private async requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': `PrivateSpace-${this.platform.toUpperCase()}/0.2 (${this.deviceName})`,
      ...((init.headers as Record<string, string>) || {}),
    };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }
    if (init.body && typeof init.body === 'string' && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    const res = await this.fetchFn(`${this.baseUrl}${path}`, {
      ...init,
      headers,
    });
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({}));
      const msg =
        typeof errBody?.error === 'string'
          ? errBody.error
          : errBody?.error?.message || `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return (await res.json()) as T;
  }

  async login(password: string): Promise<AuthSessionResponse> {
    const auth = await this.requestJson<AuthSessionResponse>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        password,
        deviceName: this.deviceName,
        platform: this.platform,
      }),
    });
    this.token = auth.token;
    await this.persistence.saveSessionToken(auth.token);
    return auth;
  }

  async logout(): Promise<void> {
    try {
      await this.requestJson('/api/v1/auth/logout', { method: 'POST' });
    } finally {
      this.token = null;
      await this.persistence.saveSessionToken(null);
    }
  }

  /**
   * Pulls incremental changes since the locally persisted `lastSyncSeq` cursor
   * and atomically updates local notes, passwords, images, videos, albums, and tombstones.
   */
  async syncDelta(): Promise<{ snapshot: MobileVaultSnapshot; delta: SyncPullResponse }> {
    const existing = (await this.persistence.loadSnapshot()) ?? {
      lastSyncSeq: 0,
      syncedAt: null,
      notes: {},
      passwords: {},
      media: {},
      albums: {},
    };

    const delta = await this.requestJson<SyncPullResponse>(
      `/api/v1/sync?since_seq=${existing.lastSyncSeq}`,
    );

    for (const note of delta.notes) {
      existing.notes[note.id] = note;
    }
    for (const pw of delta.passwords) {
      existing.passwords[pw.id] = pw;
    }
    for (const m of delta.media) {
      existing.media[m.id] = m;
    }
    for (const album of delta.albums) {
      existing.albums[album.id] = album;
    }
    for (const tomb of delta.deleted) {
      delete existing.notes[tomb.id];
      delete existing.passwords[tomb.id];
      delete existing.media[tomb.id];
      delete existing.albums[tomb.id];
    }

    existing.lastSyncSeq = delta.latestSyncSeq;
    existing.syncedAt = delta.serverTime;
    await this.persistence.saveSnapshot(existing);

    return { snapshot: existing, delta };
  }

  async createPassword(input: CreatePasswordRequest): Promise<PasswordItem> {
    const res = await this.requestJson<{ password: PasswordItem }>('/api/v1/passwords', {
      method: 'POST',
      body: JSON.stringify(input),
    });
    return res.password;
  }

  async updatePassword(id: string, input: UpdatePasswordRequest): Promise<PasswordItem> {
    const res = await this.requestJson<{ password: PasswordItem }>(
      `/api/v1/passwords/${encodeURIComponent(id)}`,
      {
        method: 'PATCH',
        body: JSON.stringify(input),
      },
    );
    return res.password;
  }

  computeTotp(secretOrUri: string, timestampMs = Date.now()): TotpTokenSnapshot | null {
    try {
      return generateTotp(secretOrUri, timestampMs);
    } catch {
      return null;
    }
  }

  generateStrongPassword(
    opts?: Partial<PasswordGeneratorOptions>,
  ): { password: string; entropy: PasswordEntropyReport } {
    const password = generateSecurePassword(opts);
    return {
      password,
      entropy: evaluatePasswordEntropy(password),
    };
  }

  /**
   * Resumable chunked upload for photos & large 4K videos on mobile networks.
   * Queries already-received chunks when resuming an interrupted uploadId.
   */
  async uploadMediaResumable(params: {
    bytes: Uint8Array;
    filename: string;
    mimeType: string;
    sha256Hex?: string;
    albumId?: string | null;
    tags?: string[];
    existingUploadId?: string;
    chunkBytes?: number;
    onProgress?: (uploadedBytes: number, totalBytes: number) => void;
  }): Promise<MediaItem> {
    let chunkBytes = params.chunkBytes ?? 512 * 1024;
    let uploadId = params.existingUploadId;
    let totalChunks = Math.max(1, Math.ceil(params.bytes.byteLength / chunkBytes));
    const completedSet = new Set<number>();

    if (uploadId) {
      const status = await this.requestJson<ResumableUploadStatusResponse>(
        `/api/v1/media/uploads/${encodeURIComponent(uploadId)}`,
      );
      totalChunks = status.totalChunks;
      chunkBytes = status.chunkBytes;
      for (const idx of status.receivedChunks) completedSet.add(idx);
    } else {
      const init = await this.requestJson<ResumableUploadInitResponse>(
        '/api/v1/media/uploads/init',
        {
          method: 'POST',
          body: JSON.stringify({
            filename: params.filename,
            mimeType: params.mimeType,
            totalBytes: params.bytes.byteLength,
            chunkBytes,
            sha256: params.sha256Hex,
            albumId: params.albumId ?? null,
            tags: params.tags ?? [],
          }),
        },
      );
      uploadId = init.uploadId;
      totalChunks = init.totalChunks;
      chunkBytes = init.chunkBytes;
    }

    for (let i = 0; i < totalChunks; i += 1) {
      if (completedSet.has(i)) continue;
      const start = i * chunkBytes;
      const end = Math.min(params.bytes.byteLength, start + chunkBytes);
      const slice = params.bytes.subarray(start, end);

      const headers: Record<string, string> = {
        'Content-Type': 'application/octet-stream',
      };
      if (this.token) headers.Authorization = `Bearer ${this.token}`;

      const chunkRes = await this.fetchFn(
        `${this.baseUrl}/api/v1/media/uploads/${encodeURIComponent(uploadId)}/chunks/${i}`,
        {
          method: 'PUT',
          headers,
          body: slice as unknown as BodyInit,
        },
      );
      if (!chunkRes.ok) {
        throw new Error(`Chunk ${i} upload failed with HTTP ${chunkRes.status}`);
      }
      params.onProgress?.(end, params.bytes.byteLength);
    }

    const done = await this.requestJson<{ media: MediaItem }>(
      `/api/v1/media/uploads/${encodeURIComponent(uploadId)}/complete`,
      {
        method: 'POST',
      },
    );
    return done.media;
  }

  getThumbnailUrl(mediaId: string): string {
    const q = this.token ? `?token=${encodeURIComponent(this.token)}` : '';
    return `${this.baseUrl}/api/v1/media/${encodeURIComponent(mediaId)}/thumbnail${q}`;
  }

  getStreamUrl(mediaId: string): string {
    const q = this.token ? `?token=${encodeURIComponent(this.token)}` : '';
    return `${this.baseUrl}/api/v1/media/${encodeURIComponent(mediaId)}/stream${q}`;
  }
}
