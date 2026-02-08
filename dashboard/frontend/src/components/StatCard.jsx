export default function StatCard({ label, value, subtitle, icon: Icon, trend }) {
  return (
    <div className="group relative bg-white/[0.02] rounded-2xl border border-gold-500/10 p-6 hover:border-gold-500/30 transition-all duration-500 hover:shadow-gold overflow-hidden">
      {/* Background glow effect */}
      <div className="absolute inset-0 bg-gradient-to-br from-gold-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
      
      <div className="relative">
        <div className="flex items-start justify-between mb-4">
          <div className="p-2.5 rounded-xl bg-gold-500/10 border border-gold-500/20">
            <Icon className="w-5 h-5 text-gold-500" />
          </div>
          {trend && (
            <span className={`text-xs font-medium px-2 py-1 rounded-full ${
              trend > 0 ? 'text-emerald-400 bg-emerald-500/10' : 'text-red-400 bg-red-500/10'
            }`}>
              {trend > 0 ? '+' : ''}{trend}%
            </span>
          )}
        </div>
        
        <p className="text-4xl font-display font-semibold text-gold-gradient mb-1">
          {value}
        </p>
        <p className="text-sm text-dark-50 font-medium">{label}</p>
        {subtitle && (
          <p className="text-xs text-dark-100 mt-1">{subtitle}</p>
        )}
      </div>
    </div>
  )
}
