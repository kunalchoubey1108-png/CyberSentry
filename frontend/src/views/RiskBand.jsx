// Band colour carries meaning; the label text always says the band too.
export const BAND_TEXT = {
  Low: 'text-neon',
  Medium: 'text-med',
  High: 'text-high',
  Critical: 'text-crit',
}

export function BandBadge({ band }) {
  return <span className={`tag glow ${BAND_TEXT[band] || 'text-mute'}`}>{String(band).toUpperCase()}</span>
}
