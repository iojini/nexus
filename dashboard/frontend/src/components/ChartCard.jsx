export default function ChartCard({ title, subtitle, children, className = '' }) {
  return (
    <div className={`bg-white/[0.02] rounded-2xl border border-gold-500/10 overflow-hidden ${className}`}>
      <div className="px-6 py-5 border-b border-gold-500/10">
        <h3 className="font-display font-semibold text-white">{title}</h3>
        {subtitle && <p className="text-xs text-dark-50 mt-1">{subtitle}</p>}
      </div>
      <div className="p-6">
        {children}
      </div>
    </div>
  )
}
