import { getDueSites, executeScan } from "@/lib/monitoring-service";

export interface SchedulerResult {
  success: boolean;
  totalSites: number;
  scanned: number;
  failed: number;
  duration: string;
  errors: string[];
}

export async function runScheduler(): Promise<SchedulerResult> {
  const start = Date.now();

  const dueSites = await getDueSites();

  let scanned = 0;
  let failed = 0;
  const errors: string[] = [];

  for (const site of dueSites) {
    try {
      console.log(`Scanning ${site.name} (${site.url})...`);

      await executeScan(site.id, "scheduled");

      scanned++;
    } catch (error) {
      failed++;

      const message =
        error instanceof Error ? error.message : "Unknown Error";

      errors.push(`${site.name}: ${message}`);

      console.error(`Failed to scan ${site.name}`, error);
    }
  }

  const duration = `${((Date.now() - start) / 1000).toFixed(2)}s`;

  return {
    success: true,
    totalSites: dueSites.length,
    scanned,
    failed,
    duration,
    errors,
  };
}