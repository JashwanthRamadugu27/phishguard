import React from 'react';
import { Zap, Cpu, Database, Radio } from 'lucide-react';

export default function Footer() {
  return (
    <footer className="w-full bg-void-950 border-t border-white/10 pt-14 pb-10 text-slate-400">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        
        <div className="grid grid-cols-1 md:grid-cols-12 gap-10 pb-10 border-b border-white/10">
          
          {/* Col 1: Brand & Concept */}
          <div className="md:col-span-5 space-y-3">
            <div className="flex items-center gap-3">
              <div className="flex items-center gap-1">
                <span className="w-1.5 h-5 bg-ember rounded-sm shadow-ember-glow"></span>
                <span className="w-1.5 h-5 bg-ember rounded-sm shadow-ember-glow"></span>
                <span className="w-1.5 h-5 bg-ember rounded-sm shadow-ember-glow"></span>
              </div>
              <span className="font-display font-black text-2xl text-white tracking-tight">
                PHISHGUARD<span className="text-xs font-mono align-super text-ember ml-0.5">™</span>
              </span>
            </div>

            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans max-w-sm">
              <strong className="text-white font-semibold">AI Powered Autonomous Phishing Defence Agent</strong> designed to intercept and eliminate zero-day phishing attacks before human error occurs.
            </p>

            <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
              <span>AUTONOMOUS AGENT ACTIVE</span>
            </div>
          </div>

          {/* Col 2: Architecture Highlights */}
          <div className="md:col-span-4 space-y-2 font-mono text-xs">
            <div className="text-slate-300 font-bold uppercase tracking-wider text-[11px] mb-2">
              CORE AGENTIC CAPABILITIES
            </div>
            <ul className="space-y-2 text-slate-400">
              <li className="flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-ember shrink-0" />
                <span>24/7 Autonomous Mailbox Interception</span>
              </li>
              <li className="flex items-center gap-2">
                <Radio className="w-3.5 h-3.5 text-ember shrink-0" />
                <span>Multi-Source Threat Telemetry (VT + urlscan)</span>
              </li>
              <li className="flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-ember shrink-0" />
                <span>Groq Llama-3.3-70B Multi-Modal Reasoning</span>
              </li>
              <li className="flex items-center gap-2">
                <Database className="w-3.5 h-3.5 text-ember shrink-0" />
                <span>Persistent Memory & Campaign Correlation</span>
              </li>
            </ul>
          </div>

          {/* Col 3: Technology Stack */}
          <div className="md:col-span-3 space-y-2 font-mono text-xs">
            <div className="text-slate-300 font-bold uppercase tracking-wider text-[11px] mb-2">
              TECH STACK
            </div>
            <div className="flex flex-wrap gap-1.5">
              {['Groq Llama-3.3', 'VirusTotal v3', 'urlscan.io', 'FastAPI', 'SQLite3', 'React', 'TailwindCSS', 'Three.js', 'Discord SecOps'].map((t, idx) => (
                <span key={idx} className="px-2.5 py-1 rounded bg-void-900 border border-white/10 text-slate-300 text-[10px]">
                  {t}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Bottom copyright */}
        <div className="pt-6 flex flex-col sm:flex-row items-center justify-between text-xs font-mono text-slate-500 gap-3">
          <div>
            © 2026 <span className="text-slate-300 font-bold">PHISHGUARD</span>. ALL RIGHTS RESERVED.
          </div>
          <div className="flex items-center gap-4 text-[11px]">
            <span>AUTONOMOUS INCIDENT RESPONSE</span>
            <span>•</span>
            <span>ZERO-DAY READY</span>
          </div>
        </div>
      </div>
    </footer>
  );
}
