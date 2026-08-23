import React, { useState } from 'react';
import { X, Zap, Terminal, ShieldAlert, CheckCircle2, ArrowRight, Play, RefreshCw, Mail, Link2, Radio, Cpu, Bell, Check, ExternalLink } from 'lucide-react';
import { audio } from '../utils/audio';

export default function ThreatSimulatorModal({ isOpen, onClose, onRunSimulation, isSimulating }) {
  const [selectedTemplate, setSelectedTemplate] = useState('bank_of_america');
  const [isCustomMode, setIsCustomMode] = useState(false);
  const [simulationState, setSimulationState] = useState(null); // 'running', 'done', null
  const [activeStepIndex, setActiveStepIndex] = useState(0);
  const [resultData, setResultData] = useState(null);

  // Form state
  const [customSubject, setCustomSubject] = useState('');
  const [customSender, setCustomSender] = useState('');
  const [customUrl, setCustomUrl] = useState('');
  const [customBody, setCustomBody] = useState('');
  const [spfStatus, setSpfStatus] = useState('fail');
  const [dkimStatus, setDkimStatus] = useState('fail');
  const [dmarcStatus, setDmarcStatus] = useState('fail');
  const [isSpoofed, setIsSpoofed] = useState(true);

  if (!isOpen) return null;

  const presets = [
    {
      id: 'bank_of_america',
      title: 'Bank of America Harvester',
      brand: 'Bank of America',
      severity: 'CRITICAL',
      subject: 'CRITICAL: Suspicious Login Attempt - Verify Account',
      sender: 'Bank of America Security <security-auth@bankofamerica-alert-center.online>',
      url: 'https://secure-login.bankofamerica.update-auth-now.top/signin',
      tags: ['Display Spoof', 'SPF Fail', 'Brand Lure'],
    },
    {
      id: 'microsoft_365',
      title: 'Microsoft 365 Tenant Expiration',
      brand: 'Microsoft 365',
      severity: 'HIGH',
      subject: 'ACTION REQUIRED: Microsoft 365 Subscription Suspended',
      sender: 'Microsoft IT Admin <no-reply@msft-enterprise-billing-portal.top>',
      url: 'https://login.microsoftonline.msft-update-auth.top/auth/verify',
      tags: ['Urgency Lure', 'DMARC Fail', 'Credential Theft'],
    },
    {
      id: 'paypal_2fa',
      title: 'PayPal 2FA Security Dispute',
      brand: 'PayPal',
      severity: 'HIGH',
      subject: 'Receipt for $849.00 USD - CryptoDirect Exchange',
      sender: 'PayPal Fraud Support <service@paypal-verification-resolve.cc>',
      url: 'https://paypal-resolution-center.auth-token.cc/dispute/resolve',
      tags: ['Invoice Fraud', 'Disposable TLD', '2FA Bypass'],
    },
    {
      id: 'docusign_invoice',
      title: 'DocuSign Malicious PO',
      brand: 'DocuSign',
      severity: 'MEDIUM',
      subject: 'DocuSign: Please review Purchase Order #PO-88291',
      sender: 'DocuSign Cloud <documents@docusign-secure-envelope.link>',
      url: 'https://docusign-secure-envelope.link/view/doc?id=88291-po',
      tags: ['Obfuscated Payload', 'Attachment Link'],
    },
    {
      id: 'safe_google',
      title: 'Safe Google Workspace Invite',
      brand: 'Google Workspace',
      severity: 'SAFE',
      subject: 'Google Calendar: Weekly Engineering Standup',
      sender: 'Google Calendar <calendar-notification@google.com>',
      url: 'https://meet.google.com/abc-defg-hij',
      tags: ['Baseline Whitelist', 'SPF/DKIM Pass', 'Clean'],
    }
  ];

  const executionSteps = [
    { num: 1, title: "Email Interception", label: "Parsing RFC-822 headers (SPF, DKIM, DMARC) & spoofing heuristics..." },
    { num: 2, title: "Link Extraction", label: "Extracting obfuscated hyperlinks, HTML anchors & defanging target URL..." },
    { num: 3, title: "Dual Threat Telemetry", label: "Concurrently querying VirusTotal (70+ engines) & urlscan.io sandbox..." },
    { num: 4, title: "Risk Score Synthesis", label: "Groq Llama-3.3-70B multi-modal AI reasoning & combined risk scoring..." },
    { num: 5, title: "Persistence & Dispatch", label: "Persisting to SQLite database & dispatching defanged SecOps Discord alert..." },
  ];

  const handleLaunch = async () => {
    setSimulationState('running');
    setActiveStepIndex(0);
    audio.scanSweep();

    const payload = isCustomMode
      ? {
          template_id: 'custom',
          custom_subject: customSubject || 'Urgent Security Verification',
          custom_sender: customSender || 'Security <admin@suspicious-domain.xyz>',
          custom_url: customUrl || 'https://auth-portal.suspicious-domain.xyz/login',
          custom_body: customBody || 'Please verify your credentials immediately.',
          spf_status: spfStatus,
          dkim_status: dkimStatus,
          dmarc_status: dmarcStatus,
          is_spoofed_display_name: isSpoofed,
        }
      : {
          template_id: selectedTemplate,
        };

    for (let i = 1; i <= 4; i++) {
      await new Promise(r => setTimeout(r, 480));
      setActiveStepIndex(i);
      audio.stepComplete();
    }

    try {
      const res = await onRunSimulation(payload);
      setResultData(res);
      setActiveStepIndex(5);
      setSimulationState('done');

      if (res?.evaluation?.verdict === 'MALICIOUS') {
        audio.threatAlert();
      } else {
        audio.safeChime();
      }
    } catch (e) {
      console.error(e);
      setSimulationState(null);
    }
  };

  const handleReset = () => {
    setSimulationState(null);
    setResultData(null);
    setActiveStepIndex(0);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md overflow-y-auto">
      <div className="relative w-full max-w-4xl cyber-panel rounded-2xl border border-ember/30 shadow-ember-lg p-6 sm:p-8 my-8 text-slate-100">
        
        {/* Modal Header */}
        <div className="flex items-center justify-between pb-4 mb-6 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-ember/20 text-ember border border-ember/40 shadow-ember-glow">
              <Zap className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono tracking-widest text-ember uppercase font-bold">
                  PHISHGUARD THREAT LAB
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-void-800 text-slate-400 border border-white/10">
                  REAL-TIME PIPELINE
                </span>
              </div>
              <h3 className="font-display font-bold text-xl sm:text-2xl text-white uppercase tracking-tight">
                Simulate Incoming Email & Phishing Pipeline
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-void-900 border border-white/10 text-slate-400 hover:text-white hover:border-ember/40 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        {simulationState === 'running' ? (
          <div className="py-12 flex flex-col items-center justify-center text-center space-y-6">
            <div className="relative w-20 h-20">
              <div className="absolute inset-0 rounded-full border-4 border-ember/20 border-t-ember animate-spin" />
              <div className="absolute inset-2 rounded-full border-2 border-cyan-500/30 border-b-cyan-400 animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.5s' }} />
              <div className="absolute inset-0 flex items-center justify-center font-mono font-bold text-ember text-sm">
                0{activeStepIndex}/05
              </div>
            </div>

            <div className="space-y-2">
              <h4 className="font-display font-bold text-xl text-white tracking-wide">
                PhishGuard Executing 5-Step Pipeline
              </h4>
              <p className="font-mono text-xs text-ember animate-pulse max-w-md">
                {executionSteps[Math.min(activeStepIndex, 4)]?.label}
              </p>
            </div>

            <div className="w-full max-w-md bg-void-900 rounded-full h-2 overflow-hidden border border-white/10">
              <div
                className="bg-gradient-to-r from-ember-600 to-ember h-full transition-all duration-300 shadow-ember-glow"
                style={{ width: `${(activeStepIndex / 5) * 100}%` }}
              />
            </div>
          </div>
        ) : simulationState === 'done' && resultData ? (
          <div className="space-y-6">
            <div className={`p-6 rounded-xl border ${
              resultData.evaluation?.verdict === 'MALICIOUS'
                ? 'bg-red-950/30 border-red-500/40 text-red-100 shadow-red-glow'
                : 'bg-emerald-950/30 border-emerald-500/40 text-emerald-100'
            }`}>
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-white/10">
                <div className="flex items-center gap-3">
                  <div className={`p-3 rounded-xl ${
                    resultData.evaluation?.verdict === 'MALICIOUS' ? 'bg-red-500/20 text-red-400' : 'bg-emerald-500/20 text-emerald-400'
                  }`}>
                    {resultData.evaluation?.verdict === 'MALICIOUS' ? <ShieldAlert className="w-8 h-8" /> : <CheckCircle2 className="w-8 h-8" />}
                  </div>
                  <div>
                    <span className="text-[10px] font-mono tracking-widest uppercase text-slate-400">
                      INVESTIGATION OUTCOME
                    </span>
                    <h4 className="font-display font-black text-2xl uppercase">
                      VERDICT: {resultData.evaluation?.verdict} ({resultData.evaluation?.confidence}% CONFIDENCE)
                    </h4>
                  </div>
                </div>

                <div className="text-right">
                  <span className="text-[10px] font-mono text-slate-400 block">IMPERSONATED BRAND</span>
                  <span className="font-mono text-sm font-bold text-white">
                    {resultData.evaluation?.brand || 'N/A'}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 text-xs font-mono">
                <div>
                  <span className="text-slate-400 block text-[10px]">DEFANGED TARGET URL</span>
                  <span className="text-ember font-semibold break-all">{resultData.target?.defanged_url}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px]">DATABASE PERSISTENCE</span>
                  <span className="text-slate-200">Logged to <code className="text-cyan-400">sentinel_memory.db</code> (Scan #{resultData.scan_id})</span>
                </div>
              </div>

              <p className="mt-4 text-sm text-slate-200 leading-relaxed font-sans bg-black/40 p-4 rounded-lg border border-white/5">
                <strong className="text-ember font-mono">AI Forensic Rationale: </strong>
                {resultData.evaluation?.reasoning}
              </p>
            </div>

            {resultData.evaluation?.recommended_actions?.length > 0 && (
              <div className="p-4 rounded-xl bg-void-900/80 border border-white/10 space-y-2">
                <span className="text-[10px] font-mono tracking-widest text-slate-400 uppercase font-semibold">
                  AUTOMATED SECOPS ACTIONS DISPATCHED
                </span>
                <ul className="space-y-1.5 font-mono text-xs text-slate-300">
                  {resultData.evaluation.recommended_actions.map((act, idx) => (
                    <li key={idx} className="flex items-center gap-2">
                      <Check className="w-3.5 h-3.5 text-ember shrink-0" />
                      <span>{act}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="flex items-center justify-end gap-3 pt-4 border-t border-white/10">
              <button
                onClick={handleReset}
                className="px-4 py-2 rounded-lg bg-void-900 border border-white/10 text-slate-300 hover:text-white font-mono text-xs"
              >
                Run Another Test
              </button>
              <button
                onClick={onClose}
                className="px-5 py-2 rounded-lg bg-ember text-white font-mono text-xs font-bold shadow-ember-glow"
              >
                Done & View in Database
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            <div className="flex items-center gap-2 p-1 bg-void-900 rounded-xl border border-white/10 max-w-xs">
              <button
                type="button"
                onClick={() => setIsCustomMode(false)}
                className={`flex-1 py-1.5 text-xs font-mono rounded-lg transition-all ${
                  !isCustomMode ? 'bg-ember text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Zero-Day Presets
              </button>
              <button
                type="button"
                onClick={() => setIsCustomMode(true)}
                className={`flex-1 py-1.5 text-xs font-mono rounded-lg transition-all ${
                  isCustomMode ? 'bg-ember text-white font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                Custom Payload
              </button>
            </div>

            {!isCustomMode ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 max-h-[380px] overflow-y-auto pr-1">
                {presets.map((p) => {
                  const isSelected = selectedTemplate === p.id;
                  const isSafe = p.severity === 'SAFE';

                  return (
                    <div
                      key={p.id}
                      onClick={() => {
                        audio.click();
                        setSelectedTemplate(p.id);
                      }}
                      className={`p-4 rounded-xl cursor-pointer transition-all duration-200 border flex flex-col justify-between ${
                        isSelected
                          ? 'cyber-panel-ember border-ember shadow-ember-glow bg-void-850'
                          : 'cyber-panel hover:border-white/20'
                      }`}
                    >
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <span className={`text-[10px] font-mono font-bold tracking-widest px-2 py-0.5 rounded ${
                            isSafe ? 'bg-emerald-950 text-emerald-400 border border-emerald-500/30' : 'bg-red-950 text-red-400 border border-red-500/30'
                          }`}>
                            {p.severity}
                          </span>
                          <span className="text-[11px] font-mono text-slate-400 font-semibold">{p.brand}</span>
                        </div>

                        <h5 className="font-display font-bold text-sm text-white mb-1">
                          {p.title}
                        </h5>
                        <p className="text-[11px] font-mono text-slate-400 truncate">
                          {p.subject}
                        </p>
                      </div>

                      <div className="mt-3 pt-2 border-t border-white/5 flex flex-wrap gap-1">
                        {p.tags.map((t, idx) => (
                          <span key={idx} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-void-800 text-slate-300">
                            {t}
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="space-y-4 max-h-[380px] overflow-y-auto pr-1 font-mono text-xs">
                <div>
                  <label className="text-slate-400 text-[10px] uppercase block mb-1">Email Subject Line</label>
                  <input
                    type="text"
                    value={customSubject}
                    onChange={(e) => setCustomSubject(e.target.value)}
                    placeholder="e.g. Critical Account Suspension Notice"
                    className="w-full px-3 py-2 rounded-lg bg-void-900 border border-white/10 text-white focus:border-ember focus:outline-none"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="text-slate-400 text-[10px] uppercase block mb-1">Sender Address (RFC-822)</label>
                    <input
                      type="text"
                      value={customSender}
                      onChange={(e) => setCustomSender(e.target.value)}
                      placeholder='Bank of America <security@auth-center.xyz>'
                      className="w-full px-3 py-2 rounded-lg bg-void-900 border border-white/10 text-white focus:border-ember focus:outline-none"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 text-[10px] uppercase block mb-1">Phishing URL Target</label>
                    <input
                      type="text"
                      value={customUrl}
                      onChange={(e) => setCustomUrl(e.target.value)}
                      placeholder='https://secure-login.bankofamerica.update-auth-now.top/signin'
                      className="w-full px-3 py-2 rounded-lg bg-void-900 border border-white/10 text-white focus:border-ember focus:outline-none"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-3 p-3 rounded-lg bg-void-900/60 border border-white/5">
                  <div>
                    <label className="text-[10px] text-slate-400 uppercase block mb-1">SPF Status</label>
                    <select
                      value={spfStatus}
                      onChange={(e) => setSpfStatus(e.target.value)}
                      className="w-full bg-void-800 text-white px-2 py-1 rounded border border-white/10 text-xs"
                    >
                      <option value="fail">FAIL (Forged)</option>
                      <option value="pass">PASS</option>
                      <option value="softfail">SOFTFAIL</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-400 uppercase block mb-1">DKIM Status</label>
                    <select
                      value={dkimStatus}
                      onChange={(e) => setDkimStatus(e.target.value)}
                      className="w-full bg-void-800 text-white px-2 py-1 rounded border border-white/10 text-xs"
                    >
                      <option value="fail">FAIL</option>
                      <option value="pass">PASS</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-slate-400 uppercase block mb-1">Display Spoof</label>
                    <button
                      type="button"
                      onClick={() => setIsSpoofed(!isSpoofed)}
                      className={`w-full py-1 rounded font-mono text-xs border ${
                        isSpoofed ? 'bg-red-950 text-red-300 border-red-500/40' : 'bg-void-800 text-slate-400 border-white/10'
                      }`}
                    >
                      {isSpoofed ? 'DETECTED' : 'NONE'}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="text-slate-400 text-[10px] uppercase block mb-1">Email Body Snippet</label>
                  <textarea
                    rows={3}
                    value={customBody}
                    onChange={(e) => setCustomBody(e.target.value)}
                    placeholder="Enter email content containing lure text..."
                    className="w-full px-3 py-2 rounded-lg bg-void-900 border border-white/10 text-white focus:border-ember focus:outline-none"
                  />
                </div>
              </div>
            )}

            <div className="flex items-center justify-between pt-4 border-t border-white/10">
              <span className="text-[11px] font-mono text-slate-400">
                Executes: 5-Step Pipeline + SQLite Write + Defanged Alert
              </span>

              <button
                type="button"
                onClick={handleLaunch}
                className="px-6 py-2.5 rounded-lg bg-gradient-to-r from-ember-600 to-ember hover:from-ember-500 hover:to-ember-600 font-mono text-xs font-bold text-white tracking-wider uppercase shadow-ember-glow flex items-center gap-2 transition-all transform hover:scale-[1.02]"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>LAUNCH SIMULATION</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
