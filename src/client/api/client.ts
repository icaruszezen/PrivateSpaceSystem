import type {
  ApiErrorResponse,
  AuthSessionResponse,
  AuthStatusResponse,
  ChangePasswordRequest,
  CipherEnvelopeInspection,
  CreateNoteRequest,
  LoginRequest,
  NoteItem,
  SessionInfo,
  SetupRequest,
  SyncPullResponse,
  UpdateNoteRequest,
  VaultSecuritySummary,
} from '@shared/types';

export class ApiClientError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiClientError';
    this.status = status;
    this.code = code;
  }
}

let unauthorizedListener: (() => void) | null = null;

export function setOnUnauthorized(listener: (() => void) | null): void {
  unauthorizedListener = listener;
}

async function requestJson<T>(
  path: string,
  options: RequestInit = {},
  suppressAuthRedirect = false,
): Promise<T> {
  const headers = new Headers(options.headers);
  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const res = await fetch(path, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!res.ok) {
    let code = 'HTTP_ERROR';
    let message = `请求失败 (${res.status})`;

    try {
      const payload = (await res.json()) as Partial<ApiErrorResponse>;
      if (payload?.error) {
        code = payload.error.code || code;
        message = payload.error.message || message;
      }
    } catch {
      // ignore non-json error body
    }

    if (res.status === 401 && !suppressAuthRedirect && unauthorizedListener) {
      unauthorizedListener();
    }

    throw new ApiClientError(res.status, code, message);
  }

  return (await res.json()) as T;
}

export const api = {
  getAuthStatus(): Promise<AuthStatusResponse> {
    return requestJson<AuthStatusResponse>('/api/v1/auth/status', {}, true);
  },

  setupAdmin(input: SetupRequest): Promise<AuthSessionResponse> {
    return requestJson<AuthSessionResponse>(
      '/api/v1/auth/setup',
      {
        method: 'POST',
        body: JSON.stringify(input),
      },
      true,
    );
  },

  login(input: LoginRequest): Promise<AuthSessionResponse> {
    return requestJson<AuthSessionResponse>(
      '/api/v1/auth/login',
      {
        method: 'POST',
        body: JSON.stringify(input),
      },
      true,
    );
  },

  logout(): Promise<{ ok: boolean }> {
    return requestJson<{ ok: boolean }>(
      '/api/v1/auth/logout',
      { method: 'POST' },
      true,
    );
  },

  changePassword(
    input: ChangePasswordRequest,
  ): Promise<{ ok: boolean; keyFingerprint: string; passwordUpdatedAt: string }> {
    return requestJson(
      '/api/v1/auth/change-password',
      {
        method: 'POST',
        body: JSON.stringify(input),
      },
      true,
    );
  },

  updateVaultName(vaultName: string): Promise<{ vaultName: string }> {
    return requestJson('/api/v1/auth/settings', {
      method: 'PATCH',
      body: JSON.stringify({ vaultName }),
    });
  },

  getSecuritySummary(): Promise<VaultSecuritySummary> {
    return requestJson('/api/v1/auth/security');
  },

  listSessions(): Promise<{ sessions: SessionInfo[] }> {
    return requestJson('/api/v1/auth/sessions');
  },

  revokeSession(id: string): Promise<{ ok: boolean }> {
    return requestJson(`/api/v1/auth/sessions/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  listNotes(includeTrashed = true): Promise<{ notes: NoteItem[]; latestSyncSeq: number }> {
    return requestJson(`/api/v1/notes?includeTrashed=${includeTrashed ? 'true' : 'false'}`);
  },

  createNote(input: CreateNoteRequest): Promise<{ note: NoteItem }> {
    return requestJson('/api/v1/notes', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },

  updateNote(id: string, input: UpdateNoteRequest): Promise<{ note: NoteItem }> {
    return requestJson(`/api/v1/notes/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(input),
    });
  },

  deleteNotePermanently(id: string): Promise<{ ok: boolean }> {
    return requestJson(`/api/v1/notes/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  },

  emptyTrash(): Promise<{ ok: boolean; purgedCount: number }> {
    return requestJson('/api/v1/notes/trash', {
      method: 'DELETE',
    });
  },

  inspectNoteCipher(id: string): Promise<{ envelope: CipherEnvelopeInspection }> {
    return requestJson(`/api/v1/notes/${encodeURIComponent(id)}/cipher`);
  },

  pullSync(sinceSeq: number): Promise<SyncPullResponse> {
    return requestJson(`/api/v1/sync?since_seq=${sinceSeq}`);
  },
};
