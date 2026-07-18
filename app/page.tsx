'use client';

import { useState, useCallback } from 'react';
import { AnimatePresence } from 'framer-motion';
import { Navbar } from '@/components/navbar';
import { Hero } from '@/components/hero';
import { LoadingAnimation } from '@/components/loading-animation';
import { ScanResults } from '@/components/scan-results';
import { ScanError } from '@/components/scan-error';
import { FeaturesSection } from '@/components/features-section';
import { HowItWorks } from '@/components/how-it-works';
import { Footer } from '@/components/footer';
import { useScan } from '@/hooks/use-scan';
import type { ScanResult } from '@/lib/types';

type ScanState = 'idle' | 'loading' | 'results' | 'error';

export default function Home() {
  const [scanState, setScanState] = useState<ScanState>('idle');
  const [scannedUrl, setScannedUrl] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);
  const [errorMessage, setErrorMessage] = useState('');

  const scanMutation = useScan();

  const handleScan = useCallback(
    (url: string) => {
      setScannedUrl(url);
      setErrorMessage('');
      setScanState('loading');

      scanMutation.mutate(
        { url },
        {
          onSuccess: (data) => {
            setResult(data);
            setScanState('results');
          },
          onError: (error: Error) => {
            setErrorMessage(error.message || 'Failed to scan the website.');
            setScanState('error');
          },
        }
      );
    },
    [scanMutation]
  );

  const handleRescan = useCallback(() => {
    setScanState('idle');
    setResult(null);
    setScannedUrl('');
    setErrorMessage('');
    scanMutation.reset();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, [scanMutation]);

  return (
    <div className="relative min-h-screen overflow-x-hidden">
      <Navbar />

      <main>
        <AnimatePresence mode="wait">
          {scanState === 'idle' && (
            <div key="idle">
              <Hero onScan={handleScan} isScanning={false} />
              <FeaturesSection />
              <HowItWorks />
            </div>
          )}
          {scanState === 'loading' && (
            <div key="loading" className="pt-20">
              <LoadingAnimation url={scannedUrl} />
            </div>
          )}
          {scanState === 'error' && (
            <div key="error" className="pt-20">
              <ScanError
                url={scannedUrl}
                message={errorMessage}
                onRetry={handleRescan}
              />
            </div>
          )}
          {scanState === 'results' && result && (
            <div key="results" className="pt-20">
              <ScanResults result={result} onRescan={handleRescan} />
            </div>
          )}
        </AnimatePresence>
      </main>

      <Footer />
    </div>
  );
}
