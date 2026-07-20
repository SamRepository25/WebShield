'use client';

import { useEffect, useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  Plus,
  Globe,
  Pencil,
  Trash2,
  RefreshCw,
  Power,
  Clock,
  ShieldCheck,
  AlertCircle,
} from 'lucide-react';
import { AppShell } from '@/components/app-shell';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
  DialogClose,
} from '@/components/ui/dialog';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { getScoreColorClass } from '@/lib/grade-utils';
import { FREQUENCY_LABELS } from '@/lib/monitoring-types';
import type { MonitoredSite, ScanFrequency } from '@/lib/monitoring-types';

interface SiteForm {
  name: string;
  url: string;
  frequency: ScanFrequency;
  monitoring_enabled: boolean;
}

const emptyForm: SiteForm = {
  name: '',
  url: '',
  frequency: 'daily',
  monitoring_enabled: true,
};

export default function MonitorPage() {
  const [sites, setSites] = useState<MonitoredSite[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<SiteForm>(emptyForm);
  const [submitting, setSubmitting] = useState(false);
  const [scanningId, setScanningId] = useState<string | null>(null);
  const [scanFeedback, setScanFeedback] = useState<{ id: string; msg: string; ok: boolean } | null>(null);

  const loadSites = useCallback(async () => {
    try {
      const res = await fetch('/api/sites');
      if (!res.ok) throw new Error('Failed to load sites.');
      const data = (await res.json()) as MonitoredSite[];
      setSites(data);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSites();
  }, [loadSites]);

  const openAdd = () => {
    setEditingId(null);
    setForm(emptyForm);
    setDialogOpen(true);
  };

  const openEdit = (site: MonitoredSite) => {
    setEditingId(site.id);
    setForm({
      name: site.name,
      url: site.url,
      frequency: site.frequency,
      monitoring_enabled: site.monitoring_enabled,
    });
    setDialogOpen(true);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      const method = editingId ? 'PUT' : 'POST';
      const endpoint = editingId ? `/api/sites/${editingId}` : '/api/sites';
      const res = await fetch(endpoint, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({ detail: 'Request failed.' }));
        throw new Error(body.detail ?? 'Request failed.');
      }
      setDialogOpen(false);
      await loadSites();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this monitored site and all its scan history?')) return;
    try {
      const res = await fetch(`/api/sites/${id}`, { method: 'DELETE' });
      if (!res.ok && res.status !== 204) throw new Error('Failed to delete site.');
      await loadSites();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleToggle = async (site: MonitoredSite) => {
    try {
      const res = await fetch(`/api/sites/${site.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ monitoring_enabled: !site.monitoring_enabled }),
      });
      if (!res.ok) throw new Error('Failed to toggle monitoring.');
      await loadSites();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleScan = async (id: string) => {
    setScanningId(id);
    setScanFeedback(null);
    try {
      const res = await fetch(`/api/sites/${id}/scan`, { method: 'POST' });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.detail ?? 'Scan failed.');
      setScanFeedback({ id, msg: `Scan complete — score ${body.result?.score ?? '—'}`, ok: true });
      await loadSites();
    } catch (err) {
      setScanFeedback({ id, msg: (err as Error).message, ok: false });
    } finally {
      setScanningId(null);
    }
  };

  return (
    <AppShell>
      <div className="mx-auto max-w-7xl px-4 py-12 sm:px-6 lg:px-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"
        >
          <div>
            <h1 className="text-3xl font-bold tracking-tight sm:text-4xl">Monitored Websites</h1>
            <p className="mt-2 text-sm text-muted-foreground">
              Add websites for continuous security monitoring and automated scans.
            </p>
          </div>
          <Button onClick={openAdd} className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90">
            <Plus className="h-4 w-4" aria-hidden="true" />
            Add Website
          </Button>
        </motion.div>

        {error && (
          <div className="mb-6 flex items-start gap-2 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}

        {loading && (
          <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="h-48 animate-pulse rounded-xl bg-secondary/40" />
            ))}
          </div>
        )}

        {!loading && sites.length === 0 && (
          <Card className="glass">
            <CardContent className="flex flex-col items-center gap-4 py-16 text-center">
              <div className="flex h-14 w-14 items-center justify-center rounded-full bg-primary/10">
                <Globe className="h-7 w-7 text-primary" aria-hidden="true" />
              </div>
              <div>
                <p className="text-sm font-medium text-foreground">No websites monitored yet</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  Add your first website to start continuous security monitoring.
                </p>
              </div>
              <Button onClick={openAdd} className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90">
                <Plus className="h-4 w-4" aria-hidden="true" />
                Add Website
              </Button>
            </CardContent>
          </Card>
        )}

        <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          {sites.map((site, idx) => (
            <motion.div
              key={site.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: idx * 0.05 }}
            >
              <Card className="glass h-full">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <CardTitle className="truncate text-base">{site.name}</CardTitle>
                      <p className="mt-0.5 truncate font-mono text-xs text-muted-foreground" title={site.url}>
                        {site.url}
                      </p>
                    </div>
                    <Badge
                      variant="outline"
                      className={
                        site.monitoring_enabled
                          ? 'border-success/30 bg-success/10 text-success'
                          : 'border-muted bg-secondary text-muted-foreground'
                      }
                    >
                      {site.monitoring_enabled ? 'Active' : 'Paused'}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <p className="text-muted-foreground">Frequency</p>
                      <p className="mt-0.5 font-medium">{FREQUENCY_LABELS[site.frequency]}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Last Scan</p>
                      <p className="mt-0.5 font-medium">
                        {site.last_scan_at
                          ? new Date(site.last_scan_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
                          : 'Never'}
                      </p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Last Score</p>
                      <p className={`mt-0.5 font-mono font-bold ${site.last_score !== null ? getScoreColorClass(site.last_score) : ''}`}>
                        {site.last_score !== null ? `${site.last_score} (${site.last_grade ?? '—'})` : '—'}
                      </p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Next Scan</p>
                      <p className="mt-0.5 font-medium">
                        {site.next_scan_at
                          ? new Date(site.next_scan_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
                          : '—'}
                      </p>
                    </div>
                  </div>

                  {scanFeedback?.id === site.id && (
                    <p className={`text-xs ${scanFeedback.ok ? 'text-success' : 'text-destructive'}`}>
                      {scanFeedback.msg}
                    </p>
                  )}

                  <div className="flex flex-wrap gap-2 pt-1">
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-1.5"
                      onClick={() => handleScan(site.id)}
                      disabled={scanningId === site.id}
                    >
                      <RefreshCw className={`h-3.5 w-3.5 ${scanningId === site.id ? 'animate-spin' : ''}`} aria-hidden="true" />
                      Scan
                    </Button>
                    <Button size="sm" variant="outline" className="gap-1.5" onClick={() => openEdit(site)}>
                      <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                      Edit
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-1.5"
                      onClick={() => handleToggle(site)}
                    >
                      <Power className="h-3.5 w-3.5" aria-hidden="true" />
                      {site.monitoring_enabled ? 'Pause' : 'Resume'}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-1.5 border-destructive/30 text-destructive hover:bg-destructive/10"
                      onClick={() => handleDelete(site.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      </div>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editingId ? 'Edit Website' : 'Add Website'}</DialogTitle>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Website Name</Label>
              <Input
                id="name"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="Marketing Site"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="url">Website URL</Label>
              <Input
                id="url"
                value={form.url}
                onChange={(e) => setForm({ ...form, url: e.target.value })}
                placeholder="example.com"
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="frequency">Scan Frequency</Label>
              <Select
                value={form.frequency}
                onValueChange={(v) => setForm({ ...form, frequency: v as ScanFrequency })}
              >
                <SelectTrigger id="frequency">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(FREQUENCY_LABELS).map(([value, label]) => (
                    <SelectItem key={value} value={value}>
                      {label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={form.monitoring_enabled}
                onChange={(e) => setForm({ ...form, monitoring_enabled: e.target.checked })}
                className="h-4 w-4 rounded border-border"
              />
              <span>Monitoring enabled</span>
            </label>
            <DialogFooter>
              <DialogClose asChild>
                <Button type="button" variant="outline">
                  Cancel
                </Button>
              </DialogClose>
              <Button type="submit" disabled={submitting} className="bg-primary text-primary-foreground hover:bg-primary/90">
                {submitting ? 'Saving…' : editingId ? 'Save Changes' : 'Add Website'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}
