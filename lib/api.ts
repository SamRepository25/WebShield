import type { ScanRequest, ScanResult, ApiError } from './types';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || '/api';

export async function scanWebsite(request: ScanRequest): Promise<ScanResult> {
  const response = await fetch(`${API_BASE_URL}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    let message = 'An unexpected error occurred.';
    try {
      const errorBody = (await response.json()) as ApiError;
      if (errorBody?.detail) {
        message = errorBody.detail;
      }
    } catch {
      // response body wasn't JSON; keep default message
    }

    const error: Error & { status?: number } = new Error(message);
    error.status = response.status;
    throw error;
  }

  return (await response.json()) as ScanResult;
}
