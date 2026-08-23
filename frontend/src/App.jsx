import React, { useState, useEffect, useRef } from 'react';
import Navbar from './components/Navbar';
import HeroSection from './components/HeroSection';
import AgentWorkflow from './components/AgentWorkflow';
import ScansDatabase from './components/ScansDatabase';
import ScanDetailModal from './components/ScanDetailModal';
import Footer from './components/Footer';
import { ApiService } from './services/api';
import { audio } from './utils/audio';

export default function App() {
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [liveActiveStep, setLiveActiveStep] = useState(null);
  const prevMaxScanIdRef = useRef(0);

  // Request browser notification permission on load
  useEffect(() => {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, []);

  // Dispatch browser desktop popup notification
  const triggerBrowserPopup = (title, body) => {
    if ('Notification' in window && Notification.permission === 'granted') {
      try {
        new Notification(title, {
          body,
          icon: '/favicon.ico',
          requireInteraction: true,
        });
      } catch (e) {
        console.warn("Notification error:", e);
      }
    }
  };

  // Load database state immediately and poll IMAP non-blocking in background
  const loadData = async (triggerImap = false) => {
    setIsRefreshing(true);
    try {
      if (triggerImap) {
        // Trigger non-blocking IMAP poll in background
        ApiService.pollImap().catch(e => console.warn("Background IMAP poll:", e));
      }

      const [statsRes, scansRes] = await Promise.all([
        ApiService.getStats(),
        ApiService.getScans({ limit: 100 }),
      ]);
      if (statsRes) setStats(statsRes);
      
      const newScans = scansRes?.scans || [];
      setScans(newScans);

      // Check if new malicious scans arrived
      if (newScans.length > 0) {
        const latestScan = newScans[0];
        if (prevMaxScanIdRef.current > 0 && latestScan.id > prevMaxScanIdRef.current) {
          if (latestScan.verdict === 'MALICIOUS') {
            audio.threatAlert();
            triggerBrowserPopup(
              "🚨 PhishGuard Threat Alert!",
              `MALICIOUS Email Intercepted: ${latestScan.email_subject || latestScan.domain}`
            );
          }
        }
        prevMaxScanIdRef.current = Math.max(...newScans.map(s => s.id));
      }
    } catch (e) {
      console.error("Failed to load dashboard data:", e);
    } finally {
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadData(true);
    // Poll every 10s — matches IMAP watcher cycle, zero server strain
    const interval = setInterval(() => loadData(true), 10000);
    return () => clearInterval(interval);
  }, []);

  // Quick single URL scan handler from Hero
  const handleScanUrl = async (url) => {
    setIsScanning(true);
    setLiveActiveStep(1);

    try {
      for (let i = 2; i <= 2; i++) {
        await new Promise(r => setTimeout(r, 400));
        setLiveActiveStep(i);
        audio.stepComplete();
      }

      const res = await ApiService.scanUrl(url);
      await loadData();

      if (res.scan_id) {
        setSelectedScanId(res.scan_id);
      }
      if (res.verdict === 'MALICIOUS') {
        audio.threatAlert();
        triggerBrowserPopup(
          "🚨 PhishGuard Threat Alert!",
          `MALICIOUS Target Identified: ${url}`
        );
      } else {
        audio.safeChime();
      }
    } catch (e) {
      console.error("Scan error:", e);
    } finally {
      setIsScanning(false);
      setTimeout(() => setLiveActiveStep(null), 3000);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-void-950 text-slate-100 selection:bg-ember selection:text-white">
      {/* Top Navbar */}
      <Navbar />

      {/* Main Single Page Dashboard Flow */}
      <main className="flex-1 w-full">
        <HeroSection
          onScanUrl={handleScanUrl}
          stats={stats}
          scans={scans}
          isScanning={isScanning}
        />
        <AgentWorkflow
          activeStep={liveActiveStep}
        />
        <ScansDatabase
          scans={scans}
          onRefresh={loadData}
          onSelectScan={(id) => setSelectedScanId(id)}
          isRefreshing={isRefreshing}
        />
      </main>

      {/* Forensic Audit Detail Drawer */}
      <ScanDetailModal
        scanId={selectedScanId}
        onClose={() => setSelectedScanId(null)}
      />

      {/* Footer */}
      <Footer />
    </div>
  );
}
