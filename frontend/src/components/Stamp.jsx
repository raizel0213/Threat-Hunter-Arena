const VARIANTS = {
  dossier: 'border-dossier text-dossier',
  terminal: 'border-terminal text-terminal',
  alert: 'border-alert text-alert',
  bone: 'border-bone text-bone',
}

export default function Stamp({ children, variant = 'dossier', rotate = -4, size = 'md', className = '' }) {
  const sizeClasses = size === 'lg' ? 'text-2xl px-5 py-2 border-[3px]' : 'text-xs px-2.5 py-1 border-2'
  return (
    <span
      className={`stamp inline-block ${sizeClasses} ${VARIANTS[variant]} ${className} select-none`}
      style={{ transform: `rotate(${rotate}deg)` }}
    >
      {children}
    </span>
  )
}
