import { useState, useEffect } from 'react'
import { Search, Filter, ExternalLink, Copy, Check, ChevronLeft, ChevronRight } from 'lucide-react'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000'

export default function IOCDatabase() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [currentPage, setCurrentPage] = useState(1)
  const [copiedId, setCopiedId] = useState(null)
  const itemsPerPage = 15

  useEffect(() => {
    fetch(`${API_URL}/dashboard-data`)
      .then(res => res.json())
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center bg-dark-gradient">
        <div className="text-center">
          <div className="w-12 h-12 rounded-xl bg-gold-subtle mx-auto mb-4 animate-pulse" />
          <p className="text-dark-50 text-sm">Loading IOC database...</p>
        </div>
      </div>
    )
  }

  const iocs = data?.recent_iocs || []
  const types = [...new Set(iocs.map(i => i.type))].filter(Boolean)

  const filtered = iocs.filter(ioc => {
    const matchesSearch = search === '' || 
      ioc.value?.toLowerCase().includes(search.toLowerCase()) ||
      ioc.type?.toLowerCase().includes(search.toLowerCase()) ||
      ioc.threat_type?.toLowerCase().includes(search.toLowerCase())
    const matchesType = typeFilter === 'all' || ioc.type === typeFilter
    return matchesSearch && matchesType
  })

  const totalPages = Math.ceil(filtered.length / itemsPerPage)
  const paginated = filtered.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage)

  const getConfidenceColor = (score) => {
    if (score >= 80) return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20'
    if (score >= 50) return 'text-gold-400 bg-gold-500/10 border-gold-500/20'
    return 'text-red-400 bg-red-500/10 border-red-500/20'
  }

  const getTypeColor = (type) => {
    const colors = {
      url: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
      domain: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
      ip: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
      hash: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      sha256: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
      md5: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
    }
    return colors[type?.toLowerCase()] || 'bg-gray-500/10 text-gray-400 border-gray-500/20'
  }

  return (
    <div className="flex-1 bg-dark-gradient overflow-auto">
      <div className="p-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-1 h-8 bg-gold-subtle rounded-full" />
            <h1 className="font-display text-3xl font-semibold text-white">
              IOC Database
            </h1>
          </div>
          <p className="text-dark-50 ml-4">
            Search and explore {iocs.length.toLocaleString()} indicators of compromise
          </p>
        </div>

        {/* Search and Filters */}
        <div className="flex flex-col md:flex-row gap-4 mb-6">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-dark-50" />
            <input
              type="text"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setCurrentPage(1) }}
              placeholder="Search IOCs by value, type, or threat..."
              className="w-full pl-12 pr-4 py-3 bg-white/[0.02] border border-gold-500/10 rounded-xl text-white placeholder-dark-50 focus:outline-none focus:border-gold-500/40 focus:ring-1 focus:ring-gold-500/20 transition-all"
            />
          </div>
          <div className="relative">
            <Filter className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-dark-50" />
            <select
              value={typeFilter}
              onChange={(e) => { setTypeFilter(e.target.value); setCurrentPage(1) }}
              className="pl-12 pr-8 py-3 bg-white/[0.02] border border-gold-500/10 rounded-xl text-white focus:outline-none focus:border-gold-500/40 appearance-none cursor-pointer min-w-[180px]"
            >
              <option value="all" className="bg-dark-600">All Types</option>
              {types.map(type => (
                <option key={type} value={type} className="bg-dark-600">{type}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Results count */}
        <div className="flex items-center justify-between mb-4">
          <p className="text-sm text-dark-50">
            Showing <span className="text-gold-400 font-medium">{paginated.length}</span> of{' '}
            <span className="text-white font-medium">{filtered.length}</span> results
          </p>
        </div>

        {/* Table */}
        <div className="bg-white/[0.02] rounded-2xl border border-gold-500/10 overflow-hidden mb-6">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gold-500/10">
                  <th className="text-left py-4 px-6 text-xs font-semibold text-dark-50 uppercase tracking-wider">Value</th>
                  <th className="text-left py-4 px-6 text-xs font-semibold text-dark-50 uppercase tracking-wider">Type</th>
                  <th className="text-left py-4 px-6 text-xs font-semibold text-dark-50 uppercase tracking-wider">Threat</th>
                  <th className="text-left py-4 px-6 text-xs font-semibold text-dark-50 uppercase tracking-wider">Confidence</th>
                  <th className="text-left py-4 px-6 text-xs font-semibold text-dark-50 uppercase tracking-wider">Source</th>
                  <th className="text-right py-4 px-6 text-xs font-semibold text-dark-50 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gold-500/5">
                {paginated.map((ioc, i) => (
                  <tr 
                    key={i} 
                    className="hover:bg-gold-500/5 transition-colors group"
                  >
                    <td className="py-4 px-6">
                      <div className="flex items-center gap-2 max-w-xs">
                        <span className="font-mono text-sm text-white truncate">{ioc.value}</span>
                      </div>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`inline-flex px-2.5 py-1 text-xs font-medium rounded-full border ${getTypeColor(ioc.type)}`}>
                        {ioc.type}
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-sm text-dark-50">{ioc.threat_type || '—'}</span>
                    </td>
                    <td className="py-4 px-6">
                      <span className={`inline-flex px-2.5 py-1 text-xs font-medium rounded-full border ${getConfidenceColor(ioc.confidence_score)}`}>
                        {ioc.confidence_score}%
                      </span>
                    </td>
                    <td className="py-4 px-6">
                      <span className="text-sm text-dark-50">{ioc.source || '—'}</span>
                    </td>
                    <td className="py-4 px-6">
                      <div className="flex items-center justify-end gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button
                          onClick={() => copyToClipboard(ioc.value, i)}
                          className="p-2 rounded-lg hover:bg-gold-500/10 text-dark-50 hover:text-gold-400 transition-colors"
                          title="Copy IOC"
                        >
                          {copiedId === i ? (
                            <Check className="w-4 h-4 text-emerald-400" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                        {ioc.type === 'url' && (
                          
                            href={`https://www.virustotal.com/gui/url/${encodeURIComponent(ioc.value)}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="p-2 rounded-lg hover:bg-gold-500/10 text-dark-50 hover:text-gold-400 transition-colors"
                            title="View on VirusTotal"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {paginated.length === 0 && (
            <div className="text-center py-12">
              <Search className="w-12 h-12 mx-auto mb-3 text-dark-100" />
              <p className="text-dark-50">No IOCs found matching your criteria</p>
            </div>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-center gap-2">
            <button
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-2 rounded-lg bg-white/[0.02] border border-gold-500/10 text-dark-50 hover:text-white hover:border-gold-500/30 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
            >
              <ChevronLeft className="w-5 h-5" />
            </button>
            
            <div className="flex items-center gap-1">
              {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                let pageNum
                if (totalPages <= 5) {
                  pageNum = i + 1
                } else if (currentPage <= 3) {
                  pageNum = i + 1
                } else if (currentPage >= totalPages - 2) {
                  pageNum = totalPages - 4 + i
                } else {
                  pageNum = currentPage - 2 + i
                }
                return (
                  <button
                    key={pageNum}
                    onClick={() => setCurrentPage(pageNum)}
                    className={`w-10 h-10 rounded-lg text-sm font-medium transition-all ${
                      currentPage === pageNum
                        ? 'bg-gold-500/20 text-gold-400 border border-gold-500/40'
                        : 'bg-white/[0.02] border border-gold-500/10 text-dark-50 hover:text-white hover:border-gold-500/30'
                    }`}
                  >
                    {pageNum}
                  </button>
                )
              })}
            </div>

            <button
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-2 rounded-lg bg-white/[0.02] border border-gold-500/10 text-dark-50 hover:text-white hover:border-gold-500/30 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
            >
              <ChevronRight className="w-5 h-5" />
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
