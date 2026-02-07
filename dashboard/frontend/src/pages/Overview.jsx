import { useState, useEffect } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, AreaChart, Area } from 'recharts'
import { Shield, AlertTriangle, Activity, Bug } from 'lucide-react'
import { API_BASE } from '../App'

const COLORS = ['#06b6d4', '#22c55e', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899', '#14b8a6', '#f97316']

export default function Overview() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const apiUrl = API_BASE ? `${API_BASE}/dashboard-data` : '/api/dashboard-data'
        const response = await fetch(apiUrl)
        if (!response.ok) throw new Error('Failed to fetch')
        const result = await response.json()
        setData(result)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
    const interval = setInterval(fetchData, 60000)
    return () => clearInterval(interval)
  }, [])

  if (loading) return <div className="p-6 text-gray-400">Loading threat intelligence...</div>
  if (error) return <div className="p-6 text-red-400">Error: {error}</div>
  if (!data || data.error) return <div className="p-6 text-yellow-400">{data?.error || 'No data available'}</div>

  const summary = data.summary || {}
  const mitreSummary = data.mitre_summary || {}
  const anomalies = data.anomalies || {}

  const pieData = Object.entries(summary.ioc_types || {}).map(([name, value]) => ({ name, value }))
  const threatData = Object.entries(summary.threat_types || {}).map(([name, value]) => ({ name, value }))
  const malwareData = (mitreSummary.malware_families || []).slice(0, 10).map(([name, count]) => ({ name, count }))
  
  const tacticsData = (mitreSummary.top_tactics || []).map(([name, count]) => ({ 
    name: name.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()), 
    count 
  }))

  const temporalData = Object.entries(data.temporal?.hourly_distribution || {}).map(([hour, count]) => ({
    hour: `${hour}:00`,
    count
  }))

  return (
    <div className="p-6 space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">Threat Intelligence Overview</h1>
          <p className="text-gray-400">Live data from {Object.keys(summary.sources || {}).length} feeds</p>
        </div>
        <div className="flex items-center gap-2 text-green-400">
          <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
          Live
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm">TOTAL IOCs</p>
              <p className="text-3xl font-bold text-white">{summary.total_iocs?.toLocaleString() || 0}</p>
              <p className="text-gray-500 text-sm">{Object.keys(summary.sources || {}).length} active feeds</p>
            </div>
            <Shield className="text-cyan-400" size={24} />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm">ATT&CK COVERAGE</p>
              <p className="text-3xl font-bold text-white">{Math.round((mitreSummary.kill_chain_coverage || 0) * 100)}%</p>
              <p className="text-gray-500 text-sm">{mitreSummary.unique_techniques || 0} techniques mapped</p>
            </div>
            <Activity className="text-green-400" size={24} />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm">ANOMALIES</p>
              <p className="text-3xl font-bold text-white">{anomalies.anomalies_found || 0}</p>
              <p className="text-gray-500 text-sm">{anomalies.anomaly_rate || 0}% anomaly rate</p>
            </div>
            <AlertTriangle className="text-yellow-400" size={24} />
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <div className="flex justify-between items-start">
            <div>
              <p className="text-gray-400 text-sm">MALWARE FAMILIES</p>
              <p className="text-3xl font-bold text-white">{(mitreSummary.malware_families || []).length}</p>
              <p className="text-gray-500 text-sm">Active threat groups</p>
            </div>
            <Bug className="text-red-400" size={24} />
          </div>
        </div>
      </div>

      {/* Charts Row 1 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h3 className="text-white font-semibold mb-4">IOC Type Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({name, percent}) => `${name} ${(percent*100).toFixed(0)}%`}>
                {pieData.map((entry, index) => <Cell key={index} fill={COLORS[index % COLORS.length]} />)}
              </Pie>
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h3 className="text-white font-semibold mb-4">Threat Types</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={threatData} layout="vertical">
              <XAxis type="number" stroke="#9ca3af" />
              <YAxis type="category" dataKey="name" stroke="#9ca3af" width={100} tick={{fontSize: 12}} />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
              <Bar dataKey="value" fill="#06b6d4" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Charts Row 2 */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h3 className="text-white font-semibold mb-4">Top Malware Families</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={malwareData}>
              <XAxis dataKey="name" stroke="#9ca3af" tick={{fontSize: 10}} angle={-45} textAnchor="end" height={80} />
              <YAxis stroke="#9ca3af" />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
              <Bar dataKey="count" fill="#8b5cf6" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <h3 className="text-white font-semibold mb-4">24hr Activity Pattern</h3>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={temporalData}>
              <XAxis dataKey="hour" stroke="#9ca3af" tick={{fontSize: 10}} />
              <YAxis stroke="#9ca3af" />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
              <Area type="monotone" dataKey="count" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.3} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* MITRE ATT&CK Coverage */}
      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <h3 className="text-white font-semibold mb-4">MITRE ATT&CK Tactic Coverage</h3>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={tacticsData}>
            <XAxis dataKey="name" stroke="#9ca3af" tick={{fontSize: 10}} angle={-45} textAnchor="end" height={80} />
            <YAxis stroke="#9ca3af" />
            <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
            <Bar dataKey="count" fill="#ef4444" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
