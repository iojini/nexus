import { NavLink } from 'react-router-dom'
import { LayoutDashboard, Grid3X3, Network, Table, Radio } from 'lucide-react'

const navItems = [
  { path: '/', label: 'Overview', icon: LayoutDashboard },
  { path: '/attack-map', label: 'ATT&CK Map', icon: Grid3X3 },
  { path: '/campaigns', label: 'Campaigns', icon: Network },
  { path: '/iocs', label: 'IOC Database', icon: Table },
  { path: '/feeds', label: 'Feed Status', icon: Radio },
]

export default function Sidebar() {
  return (
    <div className="w-64 bg-dark-700 border-r border-gold-500/10 flex flex-col">
      {/* Logo */}
      <div className="p-6 border-b border-gold-500/10">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-gold-subtle flex items-center justify-center shadow-gold">
            <span className="text-dark-700 font-display font-bold text-xl">N</span>
          </div>
          <div>
            <h1 className="font-display font-semibold text-lg tracking-widest text-white">NEXUS</h1>
            <p className="text-[11px] text-dark-50 tracking-wide">Threat Intelligence</p>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2">
        <p className="text-[10px] font-medium text-dark-50 tracking-widest uppercase px-3 mb-4">
          Navigation
        </p>
        {navItems.map(item => {
          const Icon = item.icon
          return (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `group flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all duration-300 ${
                  isActive
                    ? 'bg-gradient-to-r from-gold-500/20 to-gold-500/5 text-gold-400 shadow-inner-gold border border-gold-500/20'
                    : 'text-dark-50 hover:text-white hover:bg-white/[0.03] border border-transparent'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <Icon className={`w-5 h-5 transition-colors ${isActive ? 'text-gold-500' : 'text-dark-50 group-hover:text-gold-500/70'}`} />
                  <span>{item.label}</span>
                  {isActive && (
                    <div className="ml-auto w-1.5 h-1.5 rounded-full bg-gold-500 shadow-gold" />
                  )}
                </>
              )}
            </NavLink>
          )
        })}
      </nav>

      {/* Status */}
      <div className="p-4 m-4 rounded-xl bg-white/[0.02] border border-gold-500/10">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
            <div className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping opacity-50" />
          </div>
          <div>
            <p className="text-xs font-medium text-white">System Online</p>
            <p className="text-[10px] text-dark-50">All feeds operational</p>
          </div>
        </div>
      </div>
    </div>
  )
}
