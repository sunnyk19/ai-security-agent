import type { Branch, RepositoryPage, ScanHistoryRecord, ScanReport } from './types';

const apiBase = (import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${apiBase}${path}`, {
      ...init,
      headers: {
        Accept: 'application/json',
        ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
        ...init?.headers,
      },
    });
  } catch {
    throw new Error('Could not reach the NestJS API. Confirm the backend is running.');
  }

  if (!response.ok) {
    throw new ApiError(response.status, `Request failed with HTTP ${response.status}.`);
  }

  try {
    return (await response.json()) as T;
  } catch {
    throw new Error('The NestJS API returned an unreadable response.');
  }
}

export function listRepositories(page: number, signal?: AbortSignal) {
  return request<RepositoryPage>(`/repositories?page=${page}&perPage=100`, { signal });
}

// GitHub credentials are intentionally never accepted by this browser API client.
export function listBranches(owner: string, repository: string, signal?: AbortSignal) {
  return request<Branch[]>(
    `/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/branches`,
    { signal },
  );
}

export function scanRepository(owner: string, repository: string, branch: string) {
  return request<ScanReport>(
    `/repositories/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/scan`,
    { method: 'POST', body: JSON.stringify({ branch }) },
  );
}

export function describeApiError(error: unknown, context: 'repositories' | 'scan' = 'scan') {
  if (error instanceof ApiError && (error.status === 401 || error.status === 403)) {
    return context === 'repositories'
      ? 'Repository listing requires a valid server-side GITHUB_TOKEN with access to these repositories. The token is not sent to this browser.'
      : 'GitHub denied this scan request. Check backend token access and repository permissions.';
  }
  return error instanceof Error ? error.message : 'The request could not be completed.';
}

export function listScanHistory(limit = 20, signal?: AbortSignal) {
  return request<{ records: ScanHistoryRecord[]; count: number }>(
    `/repositories/scan-history?limit=${encodeURIComponent(String(limit))}`,
    { signal },
  );
}