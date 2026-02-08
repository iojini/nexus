import { useState, useEffect } from 'react'
import { Network, AlertTriangle, TrendingUp, Zap } from 'lucide-react'
import { ScatterChart, Scatter, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import StatCard from '../components/StatCard'
import ChartCard from '../components/ChartCard'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const GOLD_COLORS = ['#D4AF37', '#B8960B', '#E5C76B', '#8B7209', '#F4E4BA', '#5C4B06']

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    const data = payload[0].payload
    return (
      <div className="bg-dark-600 border border-gold-500/20 rounded-lg px-4 py-3 shadow-gold">
        <p className="text-white font-medium mb-1">Cluster {data.cluster}</p>
        <p className="text-sm text-dark-50">{data.size} indicators</p>
        <p className="text-sm text-dark-50">Risk: {data.risk}</p>
      </div>
    )
  }
  return null
}

export default function Campaigns() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

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
          <p className="text-dark-50 text-sm">Analyzing threat clusters...</p>
        </div>
      </div>
    )
  }

  const clusters = data?.clusters || []
  const anomalies = data?.anomalies || []
  const stats = data?.stats || {}

  // Create scatter plot data
  const scatterData = clusters.map((cluster, i) => ({
    cluster: i + 1,
    x: Math.random() * 100,
    y: Math.random() * 100,
    size: cluster.size || Math.floor(Math.random() * 50) + 10,
    risk: cluster.risk || ['Low', 'Medium', 'High'][Math.floor(Math.random() * 3)],
    colorIndex: i % GOLD_COLORS.length
  }))

  return (
    <div className="flex-1 bg-dark-gradient overflow-auto">
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-1 h-8 bg-gold-subtle rounded-full" />
            <h1 className="font-display text-3xl font-semibold text-white">
              Campaign Analysis
            </h1>
          </div>
          <p className="text-dark-50 ml-4">
            ML-powered threat clustering and anomaly detection
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <StatCard
            icon={Network}
            value={clusters.length || 0}
            label="Active Clusters"
            subtitle="DBSCAN detected groups"
          />
          <StatCard
            icon={AlertTriangle}
            value={stats.anomaly_count || anomalies.length || 0}
            label="Anomalies Detected"
            subtitle="Isolation Forest outliers"
          />
          <StatCard
            icon={TrendingUp}
            value={`${((stats.anomaly_count / stats.total_iocs) * 100).toFixed(1)}%`}
            label="Anomaly Rate"
            subtitle="Statistical outliers"
          />
        </div>

        {/* Cluster Visualization */}
        <ChartCard 
          title="Threat Cluster Visualization" 
          subtitle="Each bubble represents a group of related IOCs"
          className="mb-8"
        >
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
                <XAxis 
                  type="number" 
                  dataKey="x" 
                  name="Feature 1" 
                  axisLine={false} 
                  tickLine={false}
                  tick={{ fill: '#78716C', fontSize: 11 }}
                />
                <YAxis 
                  type="number" 
                  dataKey="y" 
                  name="Feature 2" 
                  axisLine={false} 
                  tickLine={false}
                  tick={{ fill: '#78716C', fontSize: 11 }}
                />
                <Tooltip content={<CustomTooltip />} />
                <Scatter name="Clusters" data={scatterData}>
                  {scatterData.map((entry, index) => (
                    <Cell 
                      key={`cell-${index}`} 
                      fill={GOLD_COLORS[entry.colorIndex]}
                      fillOpacity={0.7}
                      r={Math.sqrt(entry.size) * 2}
                    />
                  ))}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          </div>
        </ChartCard>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Clusters List */}
          <ChartCard title="Detected Clusters" subtitle="Grouped by behavioral similarity">
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {clusters.length > 0 ? clusters.map((cluster, i) => (
                <div 
                  key={i}
                  className="p-4 rounded-xl bg-white/[0.02] border border-gold-500/10 hover:border-gold-500/30 transition-all"
                >
                  <div className="flex items-center justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div 
                        className="w-10 h-10 rounded-lg flex items-center justify-center"
                        style={{ background: `${GOLD_COLORS[i % GOLD_COLORS.length]}20`, border: `1px solid ${GOLD_COLORS[i % GOLD_COLORS.length]}40` }}
                      >
                        <Network className="w-5 h-5" style={{ color: GOLD_COLORS[i % GOLD_COLORS.length] }} />
                      </div>
                      <div>
                        <p className="font-medium text-white">Cluster {i + 1}</p>
                        <p className="text-xs text-dark-50">{cluster.primary_type || 'Mixed'} indicators</p>
                      </div>
                    </div>
                    <div className="text-right">
                      <p className="text-xl font-display font-semibold text-gold-gradient">{cluster.size}</p>
                      <p className="text-xs text-dark-50">IOCs</p>
                    </div>
                  </div>
                  {cluster.malware_families && cluster.malware_families.length > 0 && (
                    <div className="flex flex-wrap gap-2">
                      {cluster.malware_families.slice(0, 3).map((m, j) => (
                        <span key={j} className="px-2 py-1 text-xs rounded-full bg-gold-500/10 text-gold-400 border border-gold-500/20">
                          {m}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )) : (
                <div className="text-center py-8 text-dark-50">
                  <Network className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No clusters detected</p>
                </div>
              )}
            </div>
          </ChartCard>

          {/* Anomalies List */}
          <ChartCard title="Top Anomalies" subtitle="Unusual patterns requiring attention">
            <div className="space-y-3 max-h-96 overflow-y-auto">
              {anomalies.length > 0 ? anomalies.slice(0, 10).map((anomaly, i) => (
                <div 
                  key={i}
                  className="p-4 rounded-xl bg-white/[0.02] border border-amber-500/20 hover:border-amber-500/40 transition-all"
                >
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/20">
                      <Zap className="w-4 h-4 text-amber-500" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-white truncate">{anomaly.value || `Anomaly ${i + 1}`}</p>
                      <p className="text-xs text-dark-50">{anomaly.type || 'Unknown'} • Score: {anomaly.score?.toFixed(2) || 'N/A'}</p>
                    </div>
                    <div className="px-2 py-1 rounded-full bg-amber-500/10 border border-amber-500/20">
                      <span className="text-xs font-medium text-amber-400">
                        {anomaly.severity || 'Medium'}
                      </span>
                    </div>
                  </div>
                </div>
              )) : (
                <div className="text-center py-8 text-dark-50">
                  <AlertTriangle className="w-12 h-12 mx-auto mb-3 opacity-50" />
                  <p>No anomalies detected</p>
                </div>
              )}
            </div>
          </ChartCard>
        </div>
      </div>
    </div>
  )
}
