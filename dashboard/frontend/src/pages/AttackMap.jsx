import { useState, useEffect } from 'react'
import { Target, Info } from 'lucide-react'
import ChartCard from '../components/ChartCard'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact'
]

export default function AttackMap() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [selectedTactic, setSelectedTactic] = useState(null)

  useEffect(() => {
    fetch(`${API_URL}/dashboard-data`)
      .then(res => res.json())
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-dark-gradient">
        <div className="text-center">
          <div className="w-12 h-12 rounded-xl bg-gold-subtle mx-auto mb-4 animate-pulse" />
          <p className="text-dark-50 text-sm">Loading ATT&CK data...</p>
        </div>
      </div>
    )
  }

  const techniques = data?.techniques || []
  const tacticCounts = {}
  
  TACTICS.forEach(t => { tacticCounts[t] = 0 })
  techniques.forEach(tech => {
    if (tech.tactic && tacticCounts.hasOwnProperty(tech.tactic)) {
      tacticCounts[tech.tactic] += tech.count || 1
    }
  })

  const maxCount = Math.max(...Object.values(tacticCounts), 1)

  const getIntensity = (count) => {
    if (count === 0) return 'bg-white/[0.02] border-white/5'
    const ratio = count / maxCount
    if (ratio > 0.7) return 'bg-gold-500/40 border-gold-500/60 shadow-gold'
    if (ratio > 0.4) return 'bg-gold-500/25 border-gold-500/40'
    if (ratio > 0.1) return 'bg-gold-500/15 border-gold-500/25'
    return 'bg-gold-500/8 border-gold-500/15'
  }

  return (
    <div className="flex-1 bg-dark-gradient overflow-auto">
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-1 h-8 bg-gold-subtle rounded-full" />
            <h1 className="font-display text-3xl font-semibold text-white">
              MITRE ATT&CK Coverage
            </h1>
          </div>
          <p className="text-dark-50 ml-4">
            Threat technique mapping across the cyber kill chain
          </p>
        </div>

        {/* Coverage Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <div className="bg-white/[0.02] rounded-2xl border border-gold-500/10 p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-xl bg-gold-500/10 border border-gold-500/20">
                <Target className="w-6 h-6 text-gold-500" />
              </div>
              <div>
                <p className="text-3xl font-display font-semibold text-gold-gradient">
                  {data?.stats?.attack_coverage || 0}%
                </p>
                <p className="text-sm text-dark-50">Kill Chain Coverage</p>
              </div>
            </div>
          </div>
          <div className="bg-white/[0.02] rounded-2xl border border-gold-500/10 p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-xl bg-gold-500/10 border border-gold-500/20">
                <Info className="w-6 h-6 text-gold-500" />
              </div>
              <div>
                <p className="text-3xl font-display font-semibold text-gold-gradient">
                  {techniques.length}
                </p>
                <p className="text-sm text-dark-50">Techniques Mapped</p>
              </div>
            </div>
          </div>
          <div className="bg-white/[0.02] rounded-2xl border border-gold-500/10 p-6">
            <div className="flex items-center gap-4">
              <div className="p-3 rounded-xl bg-gold-500/10 border border-gold-500/20">
                <Target className="w-6 h-6 text-gold-500" />
              </div>
              <div>
                <p className="text-3xl font-display font-semibold text-gold-gradient">
                  {TACTICS.filter(t => tacticCounts[t] > 0).length}/{TACTICS.length}
                </p>
                <p className="text-sm text-dark-50">Tactics with Coverage</p>
              </div>
            </div>
          </div>
        </div>

        {/* Kill Chain Heatmap */}
        <ChartCard 
          title="Kill Chain Heatmap" 
          subtitle="Hover over tactics to see technique counts"
          className="mb-8"
        >
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            {TACTICS.map((tactic, i) => (
              <div
                key={tactic}
                className={`relative p-4 rounded-xl border transition-all duration-300 cursor-pointer hover:scale-105 ${getIntensity(tacticCounts[tactic])}`}
                onMouseEnter={() => setSelectedTactic(tactic)}
                onMouseLeave={() => setSelectedTactic(null)}
              >
                <p className="text-xs font-medium text-white mb-2 leading-tight">{tactic}</p>
                <p className="text-2xl font-display font-semibold text-gold-gradient">
                  {tacticCounts[tactic]}
                </p>
                {selectedTactic === tactic && tacticCounts[tactic] > 0 && (
                  <div className="absolute -top-2 -right-2 w-4 h-4 bg-gold-500 rounded-full animate-ping" />
                )}
              </div>
            ))}
          </div>
          
          {/* Legend */}
          <div className="flex items-center justify-center gap-6 mt-6 pt-6 border-t border-gold-500/10">
            <span className="text-xs text-dark-50">Intensity:</span>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-gold-500/8 border border-gold-500/15" />
              <span className="text-xs text-dark-50">Low</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-gold-500/25 border border-gold-500/40" />
              <span className="text-xs text-dark-50">Medium</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="w-4 h-4 rounded bg-gold-500/40 border border-gold-500/60 shadow-gold" />
              <span className="text-xs text-dark-50">High</span>
            </div>
          </div>
        </ChartCard>

        {/* Top Techniques */}
        <ChartCard title="Top Techniques" subtitle="Most frequently observed attack techniques">
          <div className="space-y-3">
            {techniques.slice(0, 10).map((tech, i) => (
              <div 
                key={i} 
                className="flex items-center gap-4 p-4 rounded-xl bg-white/[0.02] border border-gold-500/5 hover:border-gold-500/20 transition-all"
              >
                <div className="w-10 h-10 rounded-lg bg-gold-500/10 border border-gold-500/20 flex items-center justify-center">
                  <span className="text-sm font-display font-semibold text-gold-500">
                    {i + 1}
                  </span>
                </div>
                <div className="flex-1">
                  <p className="font-medium text-white">{tech.technique_id}</p>
                  <p className="text-sm text-dark-50">{tech.tactic}</p>
                </div>
                <div className="text-right">
                  <p className="text-lg font-display font-semibold text-gold-gradient">{tech.count}</p>
                  <p className="text-xs text-dark-50">occurrences</p>
                </div>
              </div>
            ))}
          </div>
        </ChartCard>
      </div>
    </div>
  )
}
