import React from 'react';
import { Layers, ShieldAlert, Globe, Clock, ArrowUpRight, Flame } from 'lucide-react';
import { audio } from '../utils/audio';

export default function CampaignMatrix({ campaigns = [] }) {
  return (
    <section id="campaigns" className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-28">
      
      {/* Section Header */}
      <div className="mb-14">
        <div className="flex items-center gap-2 text-ember font-mono text-xs tracking-widest uppercase mb-4">
          <Flame className="w-3.5 h-3.5 text-ember" />
          <span>Correlated Threat Clusters</span>
        </div>
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-4">
          <h2 className="font-display font-black text-4xl sm:text-5xl lg:text-6xl text-white tracking-tight uppercase">
            Attack Campaign<br />Matrix
          </h2>
          <span className="font-mono text-sm text-slate-500">
            <strong className="text-white">{campaigns.length}</strong> active threat waves
          </span>
        </div>
      </div>

      {/* Campaigns Grid */}
      {campaigns.length === 0 ? (
        <div className="p-12 rounded-2xl cyber-panel border border-white/10 text-center space-y-3">
          <Layers className="w-10 h-10 text-slate-600 mx-auto" />
          <p className="font-mono text-sm text-slate-400">
            No persistent threat campaign clusters tracked in memory yet.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {campaigns.map((camp) => {
            const domainsList = camp.domains_list || [];

            return (
              <div
                key={camp.id}
                className="p-6 rounded-2xl cyber-panel border border-white/10 hover:border-ember/40 transition-all duration-300 flex flex-col justify-between space-y-6 relative overflow-hidden group"
              >
                {/* Top Glowing Ambient */}
                <div className="absolute top-0 right-0 w-32 h-32 bg-ember-500/5 rounded-full blur-2xl pointer-events-none group-hover:bg-ember-500/10 transition-colors" />

                <div>
                  {/* Campaign Header */}
                  <div className="flex items-start justify-between gap-3 mb-4">
                    <div className="space-y-1">
                      <span className="text-[10px] font-mono tracking-widest text-slate-500 uppercase">
                        CAMPAIGN #{camp.id}
                      </span>
                      <h4 className="font-display font-black text-xl text-white uppercase tracking-tight">
                        {camp.brand}
                      </h4>
                    </div>

                    <div className="p-2.5 rounded-xl bg-red-950/60 border border-red-500/30 text-red-400 flex flex-col items-center">
                      <span className="font-mono font-bold text-base leading-none">
                        {camp.attack_count}
                      </span>
                      <span className="text-[8px] font-mono tracking-widest uppercase mt-0.5">
                        ATTACKS
                      </span>
                    </div>
                  </div>

                  {/* Associated Attack Domains */}
                  <div className="space-y-2">
                    <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">
                      CORRELATED DOMAINS ({domainsList.length})
                    </span>
                    <div className="space-y-1.5 font-mono text-xs">
                      {domainsList.map((d, idx) => (
                        <div
                          key={idx}
                          className="px-3 py-1.5 rounded-lg bg-void-900/90 border border-white/5 text-ember flex items-center justify-between gap-2 break-all"
                        >
                          <span className="truncate">{d}</span>
                          <span className="text-[9px] text-slate-500 shrink-0 font-sans">DEFANGED</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Timeline Metadata */}
                <div className="pt-4 border-t border-white/5 space-y-1.5 font-mono text-[11px] text-slate-400">
                  <div className="flex justify-between items-center">
                    <span className="text-slate-500">First Intercepted:</span>
                    <span className="text-slate-300">
                      {camp.first_seen ? new Date(camp.first_seen).toLocaleDateString() : 'N/A'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-slate-500">Latest Activity:</span>
                    <span className="text-ember font-semibold">
                      {camp.last_seen ? new Date(camp.last_seen).toLocaleTimeString() : 'N/A'}
                    </span>
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
