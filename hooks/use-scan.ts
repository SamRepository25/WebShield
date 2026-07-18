'use client';

import { useMutation } from '@tanstack/react-query';
import { scanWebsite } from '@/lib/api';
import type { ScanRequest, ScanResult } from '@/lib/types';

export function useScan() {
  return useMutation<ScanResult, Error, ScanRequest>({
    mutationFn: scanWebsite,
  });
}
