'use client';

import { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Check, Loader2, Shield } from 'lucide-react';
import { loadingSteps } from '@/lib/mock-data';

interface LoadingAnimationProps {
  url: string;
}

export function LoadingAnimation({ url }: LoadingAnimationProps) {
  const [currentStep, setCurrentStep] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentStep((prev) => {
        if (prev >= loadingSteps.length - 1) {
          clearInterval(interval);
          return prev;
        }
        return prev + 1;
      });
    }, 350);
    return () => clearInterval(interval);
  }, []);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="mx-auto max-w-2xl px-4"
    >
      <div className="glass-strong relative overflow-hidden rounded-2xl p-8 sm:p-12">
        <div className="absolute inset-0 grid-bg opacity-20" />

        <div className="relative flex flex-col items-center">
          <div className="relative mb-8 h-32 w-32">
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
              className="absolute inset-0 rounded-full border-2 border-primary/20 border-t-primary"
            />
            <motion.div
              animate={{ rotate: -360 }}
              transition={{ duration: 4, repeat: Infinity, ease: 'linear' }}
              className="absolute inset-3 rounded-full border-2 border-primary/10 border-b-primary/50"
            />
            <motion.div
              animate={{ rotate: 360 }}
              transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
              className="absolute inset-6 rounded-full border-2 border-primary/10 border-l-primary/30"
            />
            <div className="absolute inset-0 flex items-center justify-center">
              <motion.div
                animate={{ scale: [1, 1.1, 1] }}
                transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
              >
                <Shield className="h-10 w-10 text-primary" />
              </motion.div>
            </div>
          </div>

          <h3 className="mb-2 text-xl font-semibold">Scanning in progress</h3>
          <p className="mb-8 text-sm text-muted-foreground">{url}</p>

          <div className="w-full max-w-md space-y-2.5">
            {loadingSteps.map((step, index) => (
              <motion.div
                key={step}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.05 }}
                className="flex items-center gap-3 text-sm"
              >
                <div className="flex h-5 w-5 shrink-0 items-center justify-center">
                  {index < currentStep ? (
                    <motion.div
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                    >
                      <Check className="h-4 w-4 text-success" />
                    </motion.div>
                  ) : index === currentStep ? (
                    <Loader2 className="h-4 w-4 animate-spin text-primary" />
                  ) : (
                    <div className="h-2 w-2 rounded-full bg-muted-foreground/30" />
                  )}
                </div>
                <span
                  className={
                    index <= currentStep
                      ? 'text-foreground'
                      : 'text-muted-foreground/50'
                  }
                >
                  {step}
                </span>
              </motion.div>
            ))}
          </div>

          <div className="mt-8 h-1 w-full max-w-md overflow-hidden rounded-full bg-secondary">
            <motion.div
              className="h-full rounded-full bg-gradient-to-r from-primary to-primary/60"
              initial={{ width: '0%' }}
              animate={{
                width: `${((currentStep + 1) / loadingSteps.length) * 100}%`,
              }}
              transition={{ duration: 0.3 }}
            />
          </div>
        </div>
      </div>
    </motion.div>
  );
}
