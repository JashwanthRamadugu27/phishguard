import React, { useState } from 'react';
import { Volume2, VolumeX, Zap } from 'lucide-react';
import { audio } from '../utils/audio';

export default function Navbar({ onOpenSimulate }) {
  const [isMuted, setIsMuted] = useState(audio.isMuted());

  const handleAudioToggle = () => {
    const muted = audio.toggleMute();
    setIsMuted(muted);
  };

  return (
    <header className="sticky top-0 z-50 w-full bg-void-950/85 backdrop-blur-xl border-b border-white/5">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-20 flex items-center justify-between">
        
        {/* Left: Brand Identity (PHISHGUARD & AI Powered Subtitle) */}
        <div className="flex items-center gap-3 cursor-pointer group">
          {/* Tactical Triple-Bar Logo Mark */}
          <div className="flex items-center gap-1.5 py-1">
            <span className="w-1.5 h-6 bg-ember rounded-sm shadow-ember-glow"></span>
            <span className="w-1.5 h-6 bg-ember rounded-sm shadow-ember-glow"></span>
            <span className="w-1.5 h-6 bg-ember rounded-sm shadow-ember-glow"></span>
            <span className="w-1.5 h-4 bg-ember/60 rounded-sm ml-0.5"></span>
          </div>

          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-display font-black text-xl md:text-2xl tracking-tighter text-white group-hover:text-ember transition-colors">
                PHISHGUARD<span className="text-xs font-mono align-super text-ember ml-0.5">™</span>
              </span>
              <span className="hidden sm:inline-block text-[9px] font-mono tracking-widest px-2 py-0.5 rounded bg-ember/10 text-ember border border-ember/20 uppercase font-semibold">
                ACTIVE
              </span>
            </div>
            <span className="text-[9px] sm:text-[10px] font-mono text-slate-400 tracking-wider uppercase">
              AI POWERED AUTONOMOUS PHISHING DEFENCE AGENT
            </span>
          </div>
        </div>

        {/* Right: Audio Toggle */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleAudioToggle}
            title={isMuted ? "Unmute Tactical Cyber Audio" : "Mute Cyber Audio"}
            className="p-2.5 rounded-lg border border-white/10 bg-void-900/80 text-slate-300 hover:text-ember hover:border-ember/40 transition-colors"
          >
            {isMuted ? <VolumeX className="w-4 h-4 text-slate-500" /> : <Volume2 className="w-4 h-4 text-ember" />}
          </button>
        </div>
      </div>
    </header>
  );
}
