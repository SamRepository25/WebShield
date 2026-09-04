export default function MaintenancePage() {
  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden bg-slate-950 px-6 text-white">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(59,130,246,0.12),_transparent_45%)]" />

      <div className="relative z-10 w-full max-w-2xl text-center">
        <div className="mx-auto mb-8 flex h-20 w-20 items-center justify-center rounded-2xl border border-blue-400/20 bg-blue-500/10 text-3xl shadow-2xl shadow-blue-950/40">
          🛡️
        </div>

        <p className="mb-3 text-sm font-semibold uppercase tracking-[0.3em] text-blue-400">
          WebShield
        </p>

        <h1 className="text-4xl font-bold tracking-tight sm:text-5xl">
          We&apos;ll be back shortly
        </h1>

        <p className="mx-auto mt-5 max-w-xl text-base leading-7 text-slate-400 sm:text-lg">
          WebShield is temporarily unavailable while we perform maintenance and
          security improvements. Your security is our priority.
        </p>

        <div className="mx-auto mt-8 flex w-fit items-center gap-3 rounded-full border border-slate-800 bg-slate-900/80 px-5 py-3 text-sm text-slate-300">
          <span className="h-2 w-2 animate-pulse rounded-full bg-blue-400" />
          Maintenance in progress
        </div>

        <p className="mt-8 text-sm text-slate-500">Please check back soon.</p>
      </div>
    </main>
  );
}
