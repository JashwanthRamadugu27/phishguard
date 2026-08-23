import React, { useEffect, useState } from 'react';
import { X, ShieldAlert, CheckCircle2, Terminal, ExternalLink, Activity, Database, Check, Layers, AlertTriangle } from 'lucide-react';
import { ApiService } from '../services/api';
import { audio } from '../utils/audio';

export default function ScanDetailModal({ scanId, onClose }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return;
    setLoading(true);
    ApiService.getScanDetails(scanId).then(res => {
      setData(res);
      setLoading(false);
    });
  }, [scanId]);

  if (!scanId) return null;

  const scan = data?.scan;
  const traces = data?.traces || [];
  const isMalicious = scan?.verdict === 'MALICIOUS';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md overflow-y-auto">
      <div className="relative w-full max-w-4xl cyber-panel rounded-2xl border border-white/15 shadow-glass p-6 sm:p-8 my-8 text-slate-100 max-h-[90vh] overflow-y-auto">
        
        {/* Header */}
        <div className="flex items-center justify-between pb-4 mb-6 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-lg border ${
              isMalicious ? 'bg-red-500/20 text-red-400 border-red-500/30' : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
            }`}>
              {isMalicious ? <ShieldAlert className="w-6 h-6" /> : <CheckCircle2 className="w-6 h-6" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono tracking-widest text-slate-400 uppercase">
                  FORENSIC AUDIT RECORD
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-void-800 text-ember border border-ember/20">
                  SCAN #{scan?.id}
                </span>
              </div>
              <h3 className="font-display font-bold text-xl sm:text-2xl text-white uppercase">
                {scan?.domain || 'Target Analysis'}
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-void-900 border border-white/10 text-slate-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {loading ? (
          <div className="py-16 text-center text-slate-400 font-mono text-xs animate-pulse">
            Loading investigation audit trail...
          </div>
        ) : (
          <div className="space-y-6">
            
            {/* Top Summary Banner */}
            <div className={`p-5 rounded-xl border ${
              isMalicious ? 'bg-red-950/20 border-red-500/30' : 'bg-emerald-950/20 border-emerald-500/30'
            }`}>
              <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-white/10">
                <div className="flex items-center gap-3">
                  <span className={`text-xs font-mono font-bold px-2.5 py-1 rounded ${
                    isMalicious ? 'bg-red-500 text-white shadow-red-glow' : 'bg-emerald-500 text-black font-bold'
                  }`}>
                    VERDICT: {scan.verdict}
                  </span>
                  <span className="text-xs font-mono text-slate-300">
                    Confidence: <strong className="text-white">{scan.confidence}%</strong>
                  </span>
                </div>

                {scan.brand && (
                  <div className="text-xs font-mono">
                    <span className="text-slate-400">Targeted Brand: </span>
                    <strong className="text-ember font-bold">{scan.brand}</strong>
                  </div>
                )}
              </div>

              <div className="mt-3 text-xs font-mono text-slate-300 space-y-1">
                <div>
                  <span className="text-slate-400">Defanged URL: </span>
                  <span className="text-ember font-semibold break-all">{scan.defanged_url}</span>
                </div>
                {scan.email_subject && (
                  <div>
                    <span className="text-slate-400">Email Subject: </span>
                    <span className="text-white">{scan.email_subject}</span>
                  </div>
                )}
                {scan.email_sender && (
                  <div>
                    <span className="text-slate-400">Sender: </span>
                    <span className="text-slate-300">{scan.email_sender}</span>
                  </div>
                )}
              </div>

              <p className="mt-3 text-sm text-slate-200 bg-void-950/80 p-3.5 rounded-lg border border-white/5 font-sans leading-relaxed">
                <strong className="text-ember font-mono">AI Reasoning: </strong>
                {scan.summary}
              </p>
            </div>

            {/* Email Header Forensics (If Available) */}
            {(scan.spf_status || scan.dkim_status || scan.is_spoofed_display_name) && (
              <div className="p-4 rounded-xl bg-void-900/80 border border-white/10 space-y-2 font-mono text-xs">
                <span className="text-[10px] uppercase text-slate-400 tracking-widest block">
                  RFC-822 EMAIL AUTHENTICATION FORENSICS
                </span>
                <div className="flex flex-wrap items-center gap-2 pt-1">
                  {scan.spf_status && (
                    <span className={`px-2.5 py-1 rounded border text-[11px] ${
                      scan.spf_status === 'pass' ? 'bg-emerald-950 text-emerald-400 border-emerald-500/30' : 'bg-red-950 text-red-400 border-red-500/30'
                    }`}>
                      SPF: {scan.spf_status.toUpperCase()}
                    </span>
                  )}
                  {scan.dkim_status && (
                    <span className={`px-2.5 py-1 rounded border text-[11px] ${
                      scan.dkim_status === 'pass' ? 'bg-emerald-950 text-emerald-400 border-emerald-500/30' : 'bg-red-950 text-red-400 border-red-500/30'
                    }`}>
                      DKIM: {scan.dkim_status.toUpperCase()}
                    </span>
                  )}
                  {scan.dmarc_status && (
                    <span className={`px-2.5 py-1 rounded border text-[11px] ${
                      scan.dmarc_status === 'pass' ? 'bg-emerald-950 text-emerald-400 border-emerald-500/30' : 'bg-red-950 text-red-400 border-red-500/30'
                    }`}>
                      DMARC: {scan.dmarc_status.toUpperCase()}
                    </span>
                  )}
                  {scan.is_spoofed_display_name ? (
                    <span className="px-2.5 py-1 rounded bg-red-950 text-red-300 border border-red-500/30 text-[11px] font-bold">
                      ⚠️ DISPLAY NAME SPOOFED
                    </span>
                  ) : null}
                </div>
              </div>
            )}

            {/* 5-Step Execution Audit Trail */}
            <div className="space-y-3">
              <span className="text-[10px] font-mono uppercase text-slate-400 tracking-widest block">
                5-STEP AGENT EXECUTION AUDIT TRAIL
              </span>

              <div className="space-y-2.5 font-mono text-xs">
                {traces.map((t, idx) => (
                  <div key={idx} className="p-3.5 rounded-xl bg-void-900/90 border border-white/5 space-y-1">
                    <div className="flex items-center justify-between text-slate-400 text-[10px]">
                      <span className="text-ember font-bold">STEP 0{t.step_num} // {t.step_name}</span>
                      <span>{new Date(t.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div className="text-slate-300 font-medium">
                      <span className="text-slate-500">Action: </span>{t.action_taken || t.action}
                    </div>
                    <div className="text-slate-200">
                      <span className="text-slate-500">Observed: </span>
                      <span className="text-emerald-400">{t.observation}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex justify-end pt-4 border-t border-white/10">
              <button
                onClick={onClose}
                className="px-5 py-2 rounded-lg bg-void-900 border border-white/15 hover:border-white/30 text-white font-mono text-xs"
              >
                Close Audit Record
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
