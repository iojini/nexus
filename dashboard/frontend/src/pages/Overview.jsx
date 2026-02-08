import { useState, useEffect } from 'react'
import { Shield, Target, AlertTriangle, Bug, Activity, TrendingUp } from 'lucide-react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts'
import StatCard from '../components/StatCard'
import ChartCard from '../components/ChartCard'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

const GOLD_COLORS = [
  '#D4AF37', '#B8960B', '#E5C76B', '#8B7209', 
  '#F4E4BA', '#5C4B06', '#FFFDF7', '#2E2603'
]

const CustomTooltip = ({ active, payload, label }) => {
  if (active && payload && payload.length) {
    return (
      <div className="bg-dark-600 border border-gold-500/20 rounded-lg px-4 py-3 shadow-gold">
        <p className="text-white font-medium">{label || payload[0].name}</p>
        <p className="text-gold-400 text-lg font-display font-semibold">{payload[0].value}</p>
      </div>
    )
  }
  return null
}

export default function Overview() {
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
          <p className="text-dark-50 text-sm">Loading intelligence data...</p>
        </div>
      </div>
    )
  }

  const stats = data?.stats || {}
  const typeData = Object.entries(data?.ioc_types || {}).map(([name, value]) => ({ name, value }))
  const threatData = Object.entries(data?.threat_types || {}).slice(0, 6).map(([name, value]) => ({ name: name || 'Unknown', value }))
  const malwareData = Object.entries(data?.malware_families || {}).slice(0, 8).map(([name, value]) => ({ name, value }))
  const hourlyData = Object.entries(data?.hourly_activity || {}).map(([hour, count]) => ({ hour: `${hour}:00`, count }))

  return (
    <div className="flex-1 bg-dark-gradient overflow-auto">
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-1 h-8 bg-gold-subtle rounded-full" />
            <h1 className="font-display text-3xl font-semibold text-white">
              Threat Intelligence Overview
            </h1>
          </div>
          <p className="text-dark-50 ml-4">
            Real-time threat landscape from {stats.feed_count || 6} active intelligence feeds
          </p>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatCard
            icon={Shield}
            value={stats.total_iocs?.toLocaleString() || '0'}
            label="Total IOCs"
            subtitle="Active indicators"
            trend={12}
          />
          <StatCard
            icon={Target}
            value={`${stats.attack_coverage || 0}%`}
            label="ATT&CK Coverage"
            subtitle={`${stats.techniques_count || 0} techniques mapped`}
          />
          <StatCard
            icon={AlertTriangle}
            value={stats.anomaly_count || 0}
            label="Anomalies"
            subtitle={`${((stats.anomaly_count / stats.total_iocs) * 100).toFixed(1)}% anomaly rate`}
          />
          <StatCard
            icon={Bug}
            value={stats.malware_families || 0}
            label="Malware Families"
            subtitle="Active threat groups"
          />
        </div>

        {/* Charts Row 1 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
          <ChartCard title="IOC Type Distribution" subtitle="Breakdown by indicator type">
            <div className="h-72 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={typeData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={100}
                    paddingAngle={2}
                    dataKey="value"
                    stroke="none"
                  >
                    {typeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={GOLD_COLORS[index % GOLD_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="flex flex-wrap gap-3 mt-4 justify-center">
              {typeData.slice(0, 5).map((item, i) => (
                <div key={i} className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-full" style={{ background: GOLD_COLORS[i] }} />
                  <span className="text-xs text-dark-50">{item.name}</span>
                </div>
              ))}
            </div>
          </ChartCard>

          <ChartCard title="Threat Types" subtitle="Classification breakdown">
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={threatData} layout="vertical" barCategoryGap={8}>
                  <XAxis type="number" axisLine={false} tickLine={false} tick={{ fill: '#78716C', fontSize: 11 }} />
                  <YAxis type="category" dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#78716C', fontSize: 11 }} width={100} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(212,175,55,0.05)' }} />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {threatData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={`rgba(212,175,55,${1 - index * 0.12})`} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
        </div>

        {/* Charts Row 2 */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ChartCard title="Top Malware Families" subtitle="Most prevalent threat actors">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={malwareData} barCategoryGap={4}>
                  <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{ fill: '#78716C', fontSize: 10, angle: -45, textAnchor: 'end' }} height={60} />
                  <YAxis axisLine={false} tickLine={false} tick={{ fill: '#78716C', fontSize: 11 }} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(212,175,55,0.05)' }} />
                  <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                    {malwareData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={GOLD_COLORS[index % GOLD_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>

          <ChartCard title="24-Hour Activity Pattern" subtitle="IOC submissions over time">
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={hourlyData}>
                  <defs>
                    <linearGradient id="goldGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#D4AF37" stopOpacity={0.4} />
                      <stop offset="100%" stopColor="#D4AF37" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="hour" axisLine={false} tickLine={false} tick={{ fill: '#78716C', fontSize: 10 }} interval={3} />
                  <YAxis axisLine={false} tickLine={false} tick={{ fill: '#78716C', fontSize: 11 }} />
                  <Tooltip content={<CustomTooltip />} />
                  <Area type="monotone" dataKey="count" stroke="#D4AF37" strokeWidth={2} fill="url(#goldGradient)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </ChartCard>
        </div>

        {/* Live indicator */}
        <div className="mt-8 flex items-center justify-center gap-2 text-dark-50 text-sm">
          <Activity className="w-4 h-4 text-gold-500 animate-pulse" />
          <span>Live data • Last updated just now</span>
        </div>
      </div>
    </div>
  )
}
