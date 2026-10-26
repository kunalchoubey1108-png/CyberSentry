// Shared terminal-style building blocks used by every view.

export function PageHeader({ command, title, children }) {
  return (
    <header className="mb-5">
      <p className="text-xs text-mute">
        <span className="text-neon">sentry@soc</span>:<span className="text-cyan">~</span>$ {command}
      </p>
      <h1 className="glow mt-1 text-2xl font-bold tracking-tight text-neon sm:text-3xl">{title}</h1>
      {children && <div className="mt-2 max-w-3xl text-sm text-mute">{children}</div>}
    </header>
  )
}

export function Panel({ title, meta, children, className = '' }) {
  return (
    <section className={`panel flex flex-col ${className}`}>
      <h2 className="panel-title">
        <span>── {title}</span>
        {meta !== undefined && <span className="text-faint normal-case tracking-normal">{meta}</span>}
      </h2>
      <div className="flex-1 px-4 py-3">{children}</div>
    </section>
  )
}

// ASCII bar "[■■■■■□□□□□]": the value is also given as text for screen readers.
export function Meter({ value, max, cells = 10, className = 'text-neon' }) {
  const filled = max > 0 ? Math.round((Math.min(value, max) / max) * cells) : 0
  return (
    <span className={`whitespace-nowrap ${className}`}>
      <span aria-hidden="true">
        [{'■'.repeat(filled)}
        <span className="text-line">{'□'.repeat(cells - filled)}</span>]
      </span>
      <span className="sr-only">
        {value} of {max}
      </span>
    </span>
  )
}

export function StatusLine({ tone = 'text-mute', children }) {
  return <p className={`cursor text-sm ${tone}`}>{children}</p>
}
