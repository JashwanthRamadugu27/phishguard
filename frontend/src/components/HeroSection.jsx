import React, { useState } from 'react';
import { Search, ArrowRight } from 'lucide-react';
import ThreatNetCanvas from './Asteroid3DCanvas';
import { audio } from '../utils/audio';

export default function HeroSection({ onScanUrl, onOpenSimulate, stats, scans = [], isScanning }) {
  const [targetUrl, setTargetUrl] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;
    audio.scanSweep();
    onScanUrl(targetUrl.trim());
  };

  return (
    <section className="relative w-full min-h-screen bg-void-950 overflow-hidden">

      {/* ── Subtle background grid ── */}
      <div className="absolute inset-0 bg-grid-pattern opacity-15 pointer-events-none" />

      {/* ── Particle canvas — RIGHT side only, strictly contained ── */}
      <div
        className="absolute top-0 right-0 bottom-0 pointer-events-none"
        style={{ width: '52%' }}
      >
        {/* Fade mask so canvas bleeds cleanly into left column */}
        <div
          className="absolute inset-0 z-10 pointer-events-none"
          style={{
            background: 'linear-gradient(to right, #05050a 0%, transparent 22%)',
          }}
        />
        <div className="w-full h-full pointer-events-auto">
          <ThreatNetCanvas onInteract={() => audio.click()} />
        </div>
      </div>

      {/* ── LEFT column — text content, always on top of canvas ── */}
      <div className="relative z-20 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-full flex items-center">
        <div className="w-full lg:w-[52%] flex flex-col justify-center py-32">

          {/* Eyebrow */}
          <div className="flex items-center gap-2.5 mb-8">
            <span className="w-2 h-2 rounded-full bg-ember animate-pulse shrink-0" />
            <span className="text-xs font-mono tracking-widest text-ember uppercase">
              Autonomous Phishing Defence
            </span>
          </div>

          {/* Display heading */}
          <h1 className="font-display font-black text-7xl sm:text-8xl lg:text-[90px] leading-[0.88] tracking-tighter text-white uppercase mb-6">
            BEYOND<br />
            <span className="text-gradient-ember">THREATS</span>
          </h1>

          <p className="text-slate-400 text-base sm:text-lg leading-relaxed max-w-md mb-10">
            <strong className="text-white font-medium">PhishGuard</strong> intercepts suspicious emails,
            extracts obfuscated links, runs dual-source threat scans, and reasons through forensic evidence
            with Groq AI — fully autonomous.
          </p>

          {/* URL Scanner input */}
          <div className="max-w-md">
            <form onSubmit={handleSubmit} className="relative flex items-center">
              <div className="absolute left-4 text-ember pointer-events-none">
                <Search className="w-4 h-4" />
              </div>
              <input
                type="text"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="Paste a suspicious URL to scan..."
                className="w-full pl-11 pr-32 py-4 rounded-2xl bg-white/5 border border-white/10 focus:border-ember/60 focus:ring-1 focus:ring-ember/30 text-sm font-mono text-white placeholder-slate-600 transition-all outline-none"
              />
              <button
                type="submit"
                disabled={isScanning}
                className="absolute right-2 top-2 bottom-2 px-5 rounded-xl bg-ember hover:bg-ember-600 font-mono text-xs font-bold text-white tracking-wider flex items-center gap-2 shadow-ember-glow transition-all disabled:opacity-50"
              >
                {isScanning ? (
                  <span className="animate-spin text-sm">⟳</span>
                ) : (
                  <>
                    <span>SCAN</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Stats strip */}
          <div className="mt-12 flex items-center gap-8 text-xs font-mono text-slate-500">
            <div>
              <span className="text-white text-xl font-bold block">{stats?.total_scans ?? 0}</span>
              Scans Stored
            </div>
            <div className="w-px h-8 bg-white/10" />
            <div>
              <span className="text-ember text-xl font-bold block">{stats?.malicious_threats ?? 0}</span>
              Threats Detected
            </div>
            <div className="w-px h-8 bg-white/10" />
            <div>
              <span className="text-emerald-400 text-xl font-bold block">99.4%</span>
              Accuracy
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
