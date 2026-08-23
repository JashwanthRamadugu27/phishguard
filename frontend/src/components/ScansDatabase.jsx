import React, { useState } from 'react';
import { Database, Search, ShieldAlert, CheckCircle2, RefreshCw, Eye, Mail } from 'lucide-react';
import { audio } from '../utils/audio';

export default function ScansDatabase({ scans = [], onRefresh, onSelectScan, isRefreshing }) {
  const [filterVerdict, setFilterVerdict] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredScans = scans.filter((s) => {
    if (filterVerdict === 'MALICIOUS' && s.verdict !== 'MALICIOUS') return false;
    if (filterVerdict === 'SAFE' && s.verdict !== 'SAFE') return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return (
        (s.url && s.url.toLowerCase().includes(q)) ||
        (s.defanged_url && s.defanged_url.toLowerCase().includes(q)) ||
        (s.domain && s.domain.toLowerCase().includes(q)) ||
        (s.email_subject && s.email_subject.toLowerCase().includes(q)) ||
        (s.email_sender && s.email_sender.toLowerCase().includes(q)) ||
        (s.brand && s.brand.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <section id="database" className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-28">
      
      {/* Section Header */}
      <div className="mb-14">
        <div className="flex items-center gap-2 text-ember font-mono text-xs tracking-widest uppercase mb-4">
          <Database className="w-3.5 h-3.5" />
          <span>sentinel_memory.db</span>
        </div>
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
          <h2 className="font-display font-black text-4xl sm:text-5xl lg:text-6xl text-white tracking-tight uppercase">
            Scanned Emails<br />Archive
          </h2>
          <div className="flex items-center gap-4">
            <span className="font-mono text-sm text-slate-500">
              <strong className="text-white">{scans.length}</strong> records
            </span>
            <button
              onClick={() => { audio.click(); onRefresh(); }}
              disabled={isRefreshing}
              className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 hover:border-ember/40 text-slate-300 hover:text-white font-mono text-xs flex items-center gap-2 transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-ember' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
        </div>
      </div>

      {/* Filter Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-4 mb-10">
        {/* Verdict Filter */}
        <div className="flex items-center gap-1 p-1 bg-white/[0.03] rounded-xl border border-white/8">
          {[
            { key: 'ALL', label: 'All Scans' },
            { key: 'MALICIOUS', label: 'Malicious' },
            { key: 'SAFE', label: 'Safe' },
          ].map(({ key, label }) => {
            const isActive = filterVerdict === key;
            return (
              <button
                key={key}
                onClick={() => { audio.click(); setFilterVerdict(key); }}
                className={`px-5 py-2 rounded-lg text-xs font-mono tracking-wide transition-all ${
                  isActive
                    ? key === 'MALICIOUS'
                      ? 'bg-red-500 text-white font-bold'
                      : key === 'SAFE'
                      ? 'bg-emerald-600 text-white font-bold'
                      : 'bg-ember text-white font-bold'
                    : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* Search */}
        <div className="relative flex-1 sm:max-w-sm">
          <Search className="w-4 h-4 text-slate-500 absolute left-4 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search domain, subject, brand..."
            className="w-full pl-11 pr-4 py-2.5 rounded-xl bg-white/[0.03] border border-white/8 text-sm font-mono text-white placeholder-slate-600 focus:border-ember/40 focus:outline-none"
          />
        </div>
      </div>

      {/* Scans List */}
      {filteredScans.length === 0 ? (
        <div className="py-20 rounded-3xl bg-white/[0.02] border border-white/8 text-center">
          <Database className="w-10 h-10 text-slate-700 mx-auto mb-4" />
          <p className="font-mono text-sm text-slate-500">
            No records matching your filter in the sentinel memory database.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredScans.map((scan) => {
            const isMalicious = scan.verdict === 'MALICIOUS';
            return (
              <div
                key={scan.id}
                onClick={() => { audio.click(); onSelectScan(scan.id); }}
                className="group p-6 sm:p-8 rounded-2xl bg-white/[0.02] border border-white/8 hover:border-white/20 hover:bg-white/[0.04] transition-all duration-200 cursor-pointer"
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                  {/* Left */}
                  <div className="flex-1 min-w-0 space-y-4">
                    {/* Top row: verdict + brand + ID */}
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className={`inline-flex items-center gap-1.5 text-xs font-mono font-bold px-3 py-1 rounded-full border ${
                        isMalicious
                          ? 'bg-red-500/10 text-red-400 border-red-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      }`}>
                        {isMalicious ? <ShieldAlert className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
                        {scan.verdict}
                      </span>

                      {scan.brand && (
                        <span className="text-xs font-mono px-3 py-1 rounded-full bg-ember/10 text-ember border border-ember/20">
                          {scan.brand}
                        </span>
                      )}

                      <span className="text-xs font-mono text-slate-600 ml-auto">
                        #{scan.id} · {scan.confidence}% confidence
                      </span>
                    </div>

                    {/* URL */}
                    <div className="font-mono text-sm break-all">
                      <span className={isMalicious ? 'text-ember/80' : 'text-emerald-400/80'}>
                        {scan.defanged_url || scan.url}
                      </span>
                    </div>

                    {/* Email metadata */}
                    {scan.email_subject && (
                      <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
                        <Mail className="w-3.5 h-3.5 shrink-0" />
                        <span className="truncate">{scan.email_subject}</span>
                        {scan.email_sender && (
                          <span className="text-slate-600 truncate hidden sm:inline">· {scan.email_sender}</span>
                        )}
                      </div>
                    )}

                    {/* AI summary */}
                    {scan.summary && (
                      <p className="text-sm text-slate-500 line-clamp-1 font-sans">
                        {scan.summary}
                      </p>
                    )}
                  </div>

                  {/* Right: action */}
                  <div className="flex items-center gap-3 shrink-0">
                    {/* SPF/DKIM compact tags */}
                    {(scan.spf_status || scan.dkim_status) && (
                      <div className="hidden sm:flex items-center gap-1.5 font-mono text-[10px]">
                        {scan.spf_status && (
                          <span className={`px-2 py-0.5 rounded-md ${scan.spf_status === 'pass' ? 'text-emerald-400 bg-emerald-950/40' : 'text-red-400 bg-red-950/40'}`}>
                            SPF
                          </span>
                        )}
                        {scan.dkim_status && (
                          <span className={`px-2 py-0.5 rounded-md ${scan.dkim_status === 'pass' ? 'text-emerald-400 bg-emerald-950/40' : 'text-red-400 bg-red-950/40'}`}>
                            DKIM
                          </span>
                        )}
                      </div>
                    )}

                    <button
                      onClick={(e) => { e.stopPropagation(); audio.click(); onSelectScan(scan.id); }}
                      className="px-4 py-2 rounded-xl bg-white/5 border border-white/10 group-hover:border-ember/40 text-slate-400 group-hover:text-white font-mono text-xs flex items-center gap-2 transition-all"
                    >
                      <Eye className="w-3.5 h-3.5 text-ember" />
                      Inspect
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
