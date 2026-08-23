import React, { useState } from 'react';
import { Mail, Link2, Terminal, Cpu, CheckCircle2 } from 'lucide-react';
import { audio } from '../utils/audio';

const workflowSteps = [
  {
    step_num: 1,
    name: "Email Interception",
    full_name: "EMAIL INTERCEPTION & HEADER ANALYSIS",
    icon: Mail,
    phase_code: "PHASE 01 // HEADER AUDIT",
    overview: "Monitors the inbox 24/7, parses raw RFC-822 headers for SPF, DKIM & DMARC alignment, and flags display-name spoofing before body evaluation.",
    badge: "24/7 ACTIVE",
    terminal_logs: [
      { time: "00.01s", tag: "INGEST", text: "Polled IMAP inbox (imap.gmail.com:993)" },
      { time: "00.03s", tag: "HEADER", text: "Parsed RFC-822 MIME envelope" },
      { time: "00.05s", tag: "AUTH", text: "SPF: FAIL | DKIM: FAIL | DMARC: FAIL", highlight: "red" },
      { time: "00.08s", tag: "SPOOF", text: "Display Name Spoofing Detected: TRUE", highlight: "amber" },
      { time: "00.12s", tag: "STATUS", text: "Header Audit Complete → Dispatching to Link Extractor", highlight: "emerald" },
    ],
    features: ["MIME RFC-822 Parsing", "SPF / DKIM / DMARC Alignment", "Display-Name Spoof Heuristics", "Zero-Body Latency"],
  },
  {
    step_num: 2,
    name: "Link Extraction",
    full_name: "DEEP OBFUSCATED LINK EXTRACTION",
    icon: Link2,
    phase_code: "PHASE 02 // URL DEFANGING",
    overview: "Extracts all embedded hyperlinks, HTML anchor targets, and URL-encoded redirects, defanging them (hxxps://) to safely neutralize malicious payloads.",
    badge: "DEFANGED",
    terminal_logs: [
      { time: "00.01s", tag: "INGEST", text: "Ingested HTML & plain text body payload" },
      { time: "00.04s", tag: "DECODE", text: "Decoded percent-encoded redirects (%3A%2F%2F)" },
      { time: "00.07s", tag: "ANCHOR", text: "Extracted anchor href: https://secure-login.bankofamerica..." },
      { time: "00.09s", tag: "DEFANG", text: "Normalized Target: hxxps://secure-login[.]bankofamerica[.]top", highlight: "amber" },
      { time: "00.14s", tag: "STATUS", text: "Payload Neutralized → Dispatching Target to Threat Intelligence", highlight: "emerald" },
    ],
    features: ["HTML Anchor Extraction", "Percent-Encoding Decoder", "Defanged Strings (hxxps://)", "Zero-Execution Guarantee"],
  },
];

export default function AgentWorkflow({ activeStep = null }) {
  const [selectedStep, setSelectedStep] = useState(1);

  const currentStep = workflowSteps.find(s => s.step_num === selectedStep) || workflowSteps[0];
  const StepIcon = currentStep.icon;

  return (
    <section id="workflow" className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-28">

      {/* Section Header */}
      <div className="mb-16">
        <div className="flex items-center gap-2 text-ember font-mono text-xs tracking-widest uppercase mb-4">
          <Cpu className="w-3.5 h-3.5" />
          <span>Autonomous Incident Pipeline</span>
        </div>
        <div className="flex flex-col md:flex-row md:items-end justify-between gap-6">
          <h2 className="font-display font-black text-4xl sm:text-5xl lg:text-6xl text-white tracking-tight uppercase">
            Agent<br />Workflow
          </h2>
        </div>
        <p className="mt-4 text-slate-500 text-base max-w-xl">
          From raw email interception to deep obfuscated link extraction — minimalist autonomous threat pipeline.
        </p>
      </div>

      {/* Step Selector — 2 Minimalist Pill Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-10">
        {workflowSteps.map((step) => {
          const Icon = step.icon;
          const isSelected = selectedStep === step.step_num;
          const isLive = activeStep === step.step_num;

          return (
            <button
              key={step.step_num}
              onClick={() => { audio.click(); setSelectedStep(step.step_num); }}
              className={`p-6 rounded-2xl text-left transition-all duration-200 border flex items-center justify-between ${
                isLive
                  ? 'bg-ember/20 border-ember shadow-ember-lg'
                  : isSelected
                  ? 'bg-white/5 border-ember/70'
                  : 'bg-white/[0.02] border-white/8 hover:border-white/20 hover:bg-white/[0.04]'
              }`}
            >
              <div className="flex items-center gap-4">
                <div className={`p-3 rounded-xl ${isSelected ? 'bg-ember text-white' : 'bg-white/5 text-slate-500'}`}>
                  <Icon className="w-5 h-5" />
                </div>
                <div>
                  <div className={`text-base font-display font-bold uppercase tracking-tight ${isSelected ? 'text-white' : 'text-slate-400'}`}>
                    0{step.step_num}. {step.name}
                  </div>
                  <div className="text-xs font-mono text-slate-500 mt-0.5">
                    {step.phase_code}
                  </div>
                </div>
              </div>

              <span className={`text-[10px] font-mono px-2.5 py-1 rounded-full ${
                isSelected ? 'bg-ember/15 text-ember border border-ember/30' : 'bg-white/5 text-slate-600'
              }`}>
                {step.badge}
              </span>
            </button>
          );
        })}
      </div>

      {/* Sleek Minimalist Terminal Card */}
      <div className="rounded-3xl bg-black/50 border border-white/10 p-8 sm:p-12 backdrop-blur-xl relative overflow-hidden">
        
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">

          {/* Left Column (5 cols): Description + Spec Tags */}
          <div className="lg:col-span-5 space-y-6">
            
            <div className="flex items-center gap-3.5">
              <div className="p-3 rounded-xl bg-ember/10 text-ember border border-ember/20">
                <StepIcon className="w-6 h-6" />
              </div>
              <div>
                <span className="text-[10px] font-mono tracking-widest text-ember font-bold uppercase block">
                  {currentStep.phase_code}
                </span>
                <h3 className="font-display font-black text-xl sm:text-2xl text-white uppercase tracking-tight">
                  {currentStep.full_name}
                </h3>
              </div>
            </div>

            <p className="text-slate-400 text-sm leading-relaxed font-sans">
              {currentStep.overview}
            </p>

            {/* Spec Features Tags */}
            <div className="space-y-2 pt-2">
              <span className="text-[10px] font-mono text-slate-500 uppercase tracking-widest block">
                CORE CAPABILITIES
              </span>
              <div className="flex flex-wrap gap-2">
                {currentStep.features.map((feat, i) => (
                  <span key={i} className="text-xs font-mono px-3 py-1 rounded-lg bg-white/[0.04] border border-white/8 text-slate-300 flex items-center gap-1.5">
                    <CheckCircle2 className="w-3 h-3 text-ember" />
                    {feat}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Right Column (7 cols): Minimal Live Cyber Terminal Feed */}
          <div className="lg:col-span-7">
            <div className="rounded-2xl bg-void-950 border border-white/10 overflow-hidden font-mono text-xs shadow-2xl">
              
              {/* Terminal Window Header */}
              <div className="px-4 py-3 bg-white/[0.03] border-b border-white/8 flex items-center justify-between text-slate-500 text-[11px]">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80 inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block" />
                  <span className="ml-2 text-slate-400 font-semibold">phishguard-agent // execution-log</span>
                </div>
                <div className="flex items-center gap-2 text-[10px] text-emerald-400">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span>SLA &lt; 0.85s</span>
                </div>
              </div>

              {/* Terminal Output Body */}
              <div className="p-5 space-y-3 bg-black/60">
                {currentStep.terminal_logs.map((log, idx) => (
                  <div key={idx} className="flex items-start gap-3 text-[11px] leading-relaxed">
                    <span className="text-slate-600 shrink-0">[{log.time}]</span>
                    <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold shrink-0 ${
                      log.highlight === 'red'
                        ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                        : log.highlight === 'amber'
                        ? 'bg-ember/20 text-ember border border-ember/30'
                        : log.highlight === 'emerald'
                        ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        : 'bg-white/5 text-slate-400'
                    }`}>
                      {log.tag}
                    </span>
                    <span className={
                      log.highlight === 'red'
                        ? 'text-red-400 font-semibold'
                        : log.highlight === 'amber'
                        ? 'text-ember font-semibold'
                        : log.highlight === 'emerald'
                        ? 'text-emerald-400 font-semibold'
                        : 'text-slate-300'
                    }>
                      {log.text}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

        </div>
      </div>
    </section>
  );
}
