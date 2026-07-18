'use client';

import { motion } from 'framer-motion';
import {
  ShieldCheck,
  Lock,
  FileCheck,
  Bug,
  Zap,
  BarChart3,
} from 'lucide-react';

const features = [
  {
    icon: ShieldCheck,
    title: 'Security Score',
    description:
      'Get an instant overall security grade from 0-100 based on multiple factors.',
  },
  {
    icon: Lock,
    title: 'HTTPS & SSL Analysis',
    description:
      'Validate SSL certificates, check TLS protocols, and monitor expiration dates.',
  },
  {
    icon: FileCheck,
    title: 'Header Inspection',
    description:
      'Comprehensive analysis of security headers like CSP, HSTS, X-Frame-Options.',
  },
  {
    icon: Bug,
    title: 'Vulnerability Detection',
    description:
      'Identify common vulnerabilities and misconfigurations with severity ratings.',
  },
  {
    icon: Zap,
    title: 'Instant Results',
    description:
      'No signup required. Get a full security report in seconds, not minutes.',
  },
  {
    icon: BarChart3,
    title: 'Actionable Insights',
    description:
      'Clear recommendations with impact analysis to help you fix issues fast.',
  },
];

export function FeaturesSection() {
  return (
    <section id="features" className="relative scroll-mt-20 py-20">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.5 }}
          className="mb-12 text-center"
        >
          <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
            Comprehensive Security Analysis
          </h2>
          <p className="mx-auto mt-4 max-w-2xl text-muted-foreground">
            Everything you need to understand and improve your website&apos;s
            security posture in one scan.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((feature, index) => {
            const Icon = feature.icon;
            return (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="glass group rounded-2xl p-6 transition-all hover:border-primary/30 hover:glow-primary"
              >
                <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-primary/10 ring-1 ring-primary/20 transition-colors group-hover:bg-primary/20">
                  <Icon className="h-6 w-6 text-primary" />
                </div>
                <h3 className="mb-2 text-lg font-semibold">{feature.title}</h3>
                <p className="text-sm text-muted-foreground">
                  {feature.description}
                </p>
              </motion.div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
