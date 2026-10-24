const BAND_CLASSES = {
  Low: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/40',
  Medium: 'bg-amber-500/15 text-amber-300 border-amber-500/40',
  High: 'bg-orange-500/15 text-orange-300 border-orange-500/40',
  Critical: 'bg-red-500/15 text-red-300 border-red-500/40',
}

export function BandBadge({ band }) {
  const tone = BAND_CLASSES[band] || 'bg-slate-500/15 text-slate-300 border-slate-500/40'
  return (
    <span className={`inline-block rounded-full border px-2.5 py-0.5 text-xs font-medium ${tone}`}>
      {band}
    </span>
  )
}
