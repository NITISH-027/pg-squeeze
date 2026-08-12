"use client";

import React, { useEffect, useState } from "react";
import { 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Cpu, 
  Database, 
  FileText, 
  Network, 
  RefreshCw, 
  ShieldAlert, 
  Terminal 
} from "lucide-react";

// Types matching API response
interface Summary {
  total_connections: number;
  short_lived: number;
  idle_pattern: number;
  chatter: number;
  heavy: number;
  normal: number;
  short_lived_ratio: number;
  processes_observed: number;
  dominant_pattern: string;
}

interface ProcessInfo {
  process_name: string;
  pid: number;
  connections: number;
  packets: number;
  bytes: number;
  avg_lifetime: number;
  short_lived: number;
  short_lived_ratio: number;
  reuse_score: number;
}

interface ConnectionEvent {
  client: string;
  server: string;
  duration: number;
  packets: number;
  bytes: number;
  process: string;
  pid: number;
  classification: string;
  status: "active" | "expired";
}

interface Hotspot {
  top_contributor: string;
  pid: number;
  connections: number;
  short_lived: number;
  short_lived_ratio: number;
  avg_lifetime: number;
  reuse_score: number;
  churn_contribution: number;
  risk: string;
  recommendation: string;
}

interface ReportData {
  mode: "live" | "sample";
  connected: boolean;
  summary: Summary;
  processes: ProcessInfo[];
  patterns: Record<string, number>;
  events: ConnectionEvent[];
  aggregate: {
    finding: string;
    recommendation: string;
  };
  hotspot: Hotspot;
  timestamp?: number;
  last_event_timestamp?: number;
}

// Sample fallback data for dashboard preview if API is completely unreachable and user wants a preview
const SAMPLE_DATA: ReportData = {
  mode: "sample",
  connected: false,
  summary: {
    total_connections: 42,
    short_lived: 28,
    idle_pattern: 8,
    chatter: 4,
    heavy: 1,
    normal: 1,
    short_lived_ratio: 66.67,
    processes_observed: 3,
    dominant_pattern: "SHORT_LIVED"
  },
  processes: [
    {
      process_name: "psql",
      pid: 14092,
      connections: 25,
      packets: 100,
      bytes: 6000,
      avg_lifetime: 0.12,
      short_lived: 25,
      short_lived_ratio: 100.0,
      reuse_score: 0.0
    },
    {
      process_name: "node",
      pid: 8241,
      connections: 12,
      packets: 480,
      bytes: 28800,
      avg_lifetime: 24.5,
      short_lived: 2,
      short_lived_ratio: 16.6,
      reuse_score: 75.0
    },
    {
      process_name: "python3",
      pid: 22134,
      connections: 5,
      packets: 1200,
      bytes: 1480000,
      avg_lifetime: 180.2,
      short_lived: 1,
      short_lived_ratio: 20.0,
      reuse_score: 75.0
    }
  ],
  patterns: {
    "SHORT_LIVED": 28,
    "IDLE_PATTERN": 8,
    "CHATTER": 4,
    "HEAVY": 1,
    "NORMAL": 1
  },
  events: [
    {
      client: "127.0.0.1:48292",
      server: "127.0.0.1:5432",
      duration: 0.05,
      packets: 4,
      bytes: 240,
      process: "psql",
      pid: 14092,
      classification: "SHORT_LIVED",
      status: "expired"
    },
    {
      client: "127.0.0.1:48294",
      server: "127.0.0.1:5432",
      duration: 0.04,
      packets: 4,
      bytes: 240,
      process: "psql",
      pid: 14092,
      classification: "SHORT_LIVED",
      status: "expired"
    },
    {
      client: "127.0.0.1:39100",
      server: "127.0.0.1:5432",
      duration: 45.2,
      packets: 82,
      bytes: 4890,
      process: "node",
      pid: 8241,
      classification: "NORMAL",
      status: "active"
    }
  ],
  aggregate: {
    finding: "CONNECTION CHURN (66.7% short-lived)",
    recommendation: "Investigate PostgreSQL connection pooling and connection reuse."
  },
  hotspot: {
    top_contributor: "psql",
    pid: 14092,
    connections: 25,
    short_lived: 25,
    short_lived_ratio: 100.0,
    avg_lifetime: 0.12,
    reuse_score: 0.0,
    churn_contribution: 89.28,
    risk: "HIGH",
    recommendation: "Prioritize connection pooling/reuse investigation for process group psql."
  }
};

export default function Dashboard() {
  const [data, setData] = useState<ReportData | null>(null);
  const [useSample, setUseSample] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sortField, setSortField] = useState<keyof ProcessInfo>("connections");
  const [sortAsc, setSortAsc] = useState(false);

  const fetchData = async () => {
    try {
      setLoading(true);
      const res = await fetch("http://127.0.0.1:8000/api/report");
      if (!res.ok) {
        throw new Error(`API returned status ${res.status}`);
      }
      const json = await res.json();
      setData(json);
      setError(null);
      setUseSample(false);
    } catch (err: any) {
      setError(err.message || "Failed to reach local API bridge");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 2000);
    return () => clearInterval(interval);
  }, []);

  const handleSort = (field: keyof ProcessInfo) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const activeData = useSample ? SAMPLE_DATA : data;
  const isDisconnected = !useSample && error !== null;

  const sortedProcesses = activeData?.processes
    ? [...activeData.processes].sort((a, b) => {
        let valA = a[sortField];
        let valB = b[sortField];
        if (typeof valA === "string") {
          return sortAsc 
            ? (valA as string).localeCompare(valB as string)
            : (valB as string).localeCompare(valA as string);
        }
        return sortAsc 
          ? (valA as number) - (valB as number)
          : (valB as number) - (valA as number);
      })
    : [];

  // Last event timestamp formatting
  const lastEventFormatted = activeData?.last_event_timestamp
    ? new Date(activeData.last_event_timestamp * 1000).toLocaleTimeString()
    : "No events";

  return (
    <div className="min-h-screen bg-[#0a0a0c] text-[#e4e4e7] p-4 md:p-6 font-mono selection:bg-blue-500 selection:text-white">
      {/* Top Header */}
      <header className="max-w-7xl mx-auto mb-6 flex flex-col md:flex-row md:items-center justify-between border-b border-[#1f1f23] pb-6 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-950/40 border border-blue-900/60 rounded text-blue-400">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-white">PG-SQUEEZE</h1>
              <p className="text-xs text-zinc-500">eBPF PostgreSQL Connection Observer</p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3 md:gap-4">
          {/* Data timestamp */}
          <div className="text-xs text-zinc-500">
            Last Event: <span className="text-zinc-300 font-bold">{lastEventFormatted}</span>
          </div>

          {/* Status Indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-[#121215] border border-[#1f1f23] rounded">
            {isDisconnected ? (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
                </span>
                <span className="text-[10px] font-semibold text-red-400 uppercase">Disconnected</span>
              </>
            ) : activeData?.mode === "live" && activeData.connected ? (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                </span>
                <span className="text-[10px] font-semibold text-emerald-400 uppercase">Live</span>
              </>
            ) : (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500"></span>
                </span>
                <span className="text-[10px] font-semibold text-amber-400 uppercase">Sample Mode</span>
              </>
            )}
          </div>

          <button 
            onClick={() => {
              if (isDisconnected) {
                setUseSample(true);
                setError(null);
              } else if (useSample) {
                setUseSample(false);
                fetchData();
              } else {
                fetchData();
              }
            }}
            className="flex items-center gap-2 px-4 py-1.5 bg-zinc-900 border border-zinc-800 text-xs font-medium text-zinc-300 hover:bg-zinc-800 rounded transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            {useSample ? "Try Reconnecting" : "Force Refresh"}
          </button>
        </div>
      </header>

      {isDisconnected && (
        <div className="max-w-7xl mx-auto mb-6 p-4 bg-red-950/20 border border-red-900/40 rounded text-red-200 text-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-5 h-5 text-red-500 shrink-0" />
            <div>
              <p className="font-bold">API Connection Lost</p>
              <p className="text-red-300/80">Cannot reach local bridge API at http://127.0.0.1:8000/api/report. Check if the uvicorn server is running.</p>
            </div>
          </div>
          <button 
            onClick={() => {
              setUseSample(true);
              setError(null);
            }}
            className="px-3 py-1 bg-red-900/40 border border-red-800 hover:bg-red-800/60 rounded transition text-[10px] font-bold uppercase shrink-0"
          >
            Load Sample Data
          </button>
        </div>
      )}

      {/* Main Grid */}
      <main className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-12 gap-6">
        
        {/* SECTION 1: OVERVIEW CARD (Grid Span 8) */}
        <div className="lg:col-span-8 bg-[#121215] border border-[#1f1f23] rounded p-6">
          <h2 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-6 flex items-center gap-2">
            <Activity className="w-3.5 h-3.5" /> Overview
          </h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <div className="border-r border-[#1f1f23] last:border-0 pr-4">
              <p className="text-xs text-zinc-500 mb-1">Connections</p>
              <p className="text-2xl font-bold text-white">{activeData?.summary.total_connections ?? 0}</p>
            </div>
            <div className="border-r border-[#1f1f23] last:border-0 pr-4">
              <p className="text-xs text-zinc-500 mb-1">Short-Lived</p>
              <p className="text-2xl font-bold text-white">{activeData?.summary.short_lived ?? 0}</p>
            </div>
            <div className="border-r border-[#1f1f23] last:border-0 pr-4">
              <p className="text-xs text-zinc-500 mb-1">Short-Lived Ratio</p>
              <p className={`text-2xl font-bold ${activeData && activeData.summary.short_lived_ratio > 50 ? 'text-red-400' : 'text-emerald-400'}`}>
                {activeData?.summary.short_lived_ratio?.toFixed(1) ?? "0.0"}%
              </p>
            </div>
            <div>
              <p className="text-xs text-zinc-500 mb-1">Dominant Pattern</p>
              <p className="text-xs font-bold text-zinc-300 mt-2.5 truncate max-w-[125px] bg-[#1c1c22] border border-zinc-800 px-2 py-0.5 rounded uppercase">
                {activeData?.summary.dominant_pattern ?? "NONE"}
              </p>
            </div>
          </div>
        </div>

        {/* SECTION 2: CONNECTION PATTERNS (Grid Span 4) */}
        <div className="lg:col-span-4 bg-[#121215] border border-[#1f1f23] rounded p-6">
          <h2 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-6 flex items-center gap-2">
            <Network className="w-3.5 h-3.5" /> Connection Patterns
          </h2>
          <div className="space-y-4">
            {Object.entries(activeData?.patterns ?? {}).map(([pattern, count]) => {
              const total = activeData?.summary.total_connections || 1;
              const pct = (count / total) * 100;
              return (
                <div key={pattern} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-zinc-400 font-medium">{pattern}</span>
                    <span className="text-zinc-500">{count}</span>
                  </div>
                  <div className="w-full bg-[#1c1c22] rounded-full h-1.5 overflow-hidden">
                    <div 
                      className={`h-full rounded-full transition-all duration-500 ${
                        pattern === "SHORT_LIVED" ? "bg-red-500/80" :
                        pattern === "IDLE_PATTERN" ? "bg-amber-500/80" :
                        pattern === "CHATTER" ? "bg-blue-500/80" :
                        pattern === "HEAVY" ? "bg-purple-500/80" : "bg-emerald-500/80"
                      }`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* SECTION 5: INVESTIGATION GUIDANCE (Grid Span 12) */}
        <div className="lg:col-span-12 bg-[#121215] border border-[#1f1f23] rounded p-6">
          <h2 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-6 flex items-center gap-2">
            <FileText className="w-3.5 h-3.5" /> Investigation Guidance
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-[#18181c]/40 border border-[#24242b] p-4 rounded">
              <p className="text-xs text-zinc-500 uppercase tracking-wider mb-2 font-bold">Observation</p>
              <p className="text-xs text-zinc-300 font-medium leading-relaxed">
                {activeData?.summary && activeData.summary.total_connections > 0 
                  ? `${activeData.summary.short_lived}/${activeData.summary.total_connections} observed connections were short-lived.`
                  : "No connections observed yet."}
              </p>
            </div>
            <div className="bg-[#18181c]/40 border border-[#24242b] p-4 rounded">
              <p className="text-xs text-zinc-500 uppercase tracking-wider mb-2 font-bold">Interpretation</p>
              <p className="text-xs text-zinc-300 font-medium leading-relaxed">
                {activeData?.summary && activeData.summary.short_lived_ratio > 25
                  ? "The observed pattern is consistent with repeated connection establishment."
                  : "The connection pattern appears stable with normal lifetimes."}
              </p>
            </div>
            <div className="bg-[#18181c]/40 border border-[#24242b] p-4 rounded">
              <p className="text-xs text-zinc-500 uppercase tracking-wider mb-2 font-bold">Recommendation</p>
              <p className="text-xs text-zinc-300 font-medium leading-relaxed">
                {activeData?.aggregate.recommendation ?? "Continue monitoring connection behavior."}
              </p>
            </div>
          </div>
        </div>

        {/* SECTION 3: PROCESS FORENSICS (Grid Span 12) */}
        <div className="lg:col-span-12 bg-[#121215] border border-[#1f1f23] rounded overflow-hidden">
          <div className="p-6 border-b border-[#1f1f23]">
            <h2 className="text-xs font-bold text-zinc-500 uppercase tracking-widest flex items-center gap-2">
              <Cpu className="w-3.5 h-3.5" /> Process Forensics
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs min-w-[800px]">
              <thead>
                <tr className="bg-[#16161a] border-b border-[#1f1f23] text-zinc-400">
                  <th className="p-4 font-bold cursor-pointer hover:bg-zinc-800" onClick={() => handleSort("process_name")}>Process</th>
                  <th className="p-4 font-bold cursor-pointer hover:bg-zinc-800" onClick={() => handleSort("pid")}>PID</th>
                  <th className="p-4 font-bold cursor-pointer hover:bg-zinc-800" onClick={() => handleSort("connections")}>Connections</th>
                  <th className="p-4 font-bold cursor-pointer hover:bg-zinc-800" onClick={() => handleSort("packets")}>Packets</th>
                  <th className="p-4 font-bold cursor-pointer hover:bg-zinc-800" onClick={() => handleSort("bytes")}>Bytes</th>
                  <th className="p-4 font-bold cursor-pointer hover:bg-zinc-800" onClick={() => handleSort("short_lived")}>Short-Lived</th>
                  <th className="p-4 font-bold cursor-pointer hover:bg-zinc-800" onClick={() => handleSort("short_lived_ratio")}>Short-Lived Ratio</th>
                  <th className="p-4 font-bold cursor-pointer hover:bg-zinc-800" onClick={() => handleSort("avg_lifetime")}>Avg Lifetime</th>
                  <th className="p-4 font-bold cursor-pointer hover:bg-zinc-800" onClick={() => handleSort("reuse_score")}>Reuse Score</th>
                </tr>
              </thead>
              <tbody>
                {sortedProcesses.map((p, idx) => (
                  <tr key={`${p.pid}-${idx}`} className="border-b border-[#1f1f23]/60 hover:bg-[#16161a]/30 text-zinc-300">
                    <td className="p-4 font-bold text-white">{p.process_name}</td>
                    <td className="p-4 text-zinc-500">{p.pid}</td>
                    <td className="p-4">{p.connections}</td>
                    <td className="p-4">{p.packets}</td>
                    <td className="p-4">{p.bytes.toLocaleString()} B</td>
                    <td className="p-4">{p.short_lived}</td>
                    <td className="p-4">{p.short_lived_ratio.toFixed(1)}%</td>
                    <td className="p-4">{p.avg_lifetime.toFixed(3)}s</td>
                    <td className="p-4 font-bold">
                      <span className={`px-2 py-0.5 rounded text-[10px] ${
                        p.reuse_score >= 75 ? 'bg-emerald-950/40 text-emerald-400 border border-emerald-900/40' :
                        p.reuse_score >= 50 ? 'bg-amber-950/40 text-amber-400 border border-amber-900/40' :
                        'bg-red-950/40 text-red-400 border border-red-900/40'
                      }`}>
                        {p.reuse_score.toFixed(0)}/100
                      </span>
                    </td>
                  </tr>
                ))}
                {sortedProcesses.length === 0 && (
                  <tr>
                    <td colSpan={9} className="p-8 text-center text-zinc-600">No processes monitored.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* SECTION 6: HOTSPOT (Grid Span 4) */}
        <div className="lg:col-span-4 bg-[#121215] border border-[#1f1f23] rounded p-6">
          <h2 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-6 flex items-center gap-2">
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" /> Hotspot
          </h2>
          {activeData?.hotspot.top_contributor && activeData.hotspot.top_contributor !== "None" ? (
            <div className="space-y-4">
              <div className="flex justify-between items-center bg-red-950/20 border border-red-900/30 p-3 rounded">
                <div>
                  <p className="text-[10px] text-zinc-500 uppercase">Process Group</p>
                  <p className="text-base font-bold text-white">{activeData.hotspot.top_contributor}</p>
                </div>
                <div className="text-right">
                  <p className="text-[10px] text-zinc-500 uppercase">Risk Level</p>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    activeData.hotspot.risk === "HIGH" ? "bg-red-950/60 text-red-400 border border-red-900" :
                    activeData.hotspot.risk === "MEDIUM" ? "bg-amber-950/60 text-amber-400 border border-amber-900" :
                    "bg-zinc-800 text-zinc-400"
                  }`}>
                    {activeData.hotspot.risk}
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs font-mono">
                <div>
                  <span className="text-zinc-500">Representative PID</span>
                  <p className="font-bold text-zinc-300">{activeData.hotspot.pid}</p>
                </div>
                <div>
                  <span className="text-zinc-500">Connections</span>
                  <p className="font-bold text-zinc-300">{activeData.hotspot.connections}</p>
                </div>
                <div>
                  <span className="text-zinc-500">Short-Lived Count</span>
                  <p className="font-bold text-zinc-300">{activeData.hotspot.short_lived}</p>
                </div>
                <div>
                  <span className="text-zinc-500">Short-Lived Ratio</span>
                  <p className="font-bold text-zinc-300">{activeData.hotspot.short_lived_ratio.toFixed(1)}%</p>
                </div>
                <div>
                  <span className="text-zinc-500">Average Lifetime</span>
                  <p className="font-bold text-zinc-300">{activeData.hotspot.avg_lifetime.toFixed(3)}s</p>
                </div>
                <div>
                  <span className="text-zinc-500">Reuse Score</span>
                  <p className="font-bold text-zinc-300">{activeData.hotspot.reuse_score.toFixed(0)}/100</p>
                </div>
              </div>

              <div className="border-t border-[#1f1f23] pt-4">
                <span className="text-xs text-zinc-500 block mb-1">Share of observed short-lived connections</span>
                <p className="text-sm font-bold text-white">{activeData.hotspot.churn_contribution.toFixed(1)}%</p>
              </div>

              <div className="border-t border-[#1f1f23] pt-4">
                <span className="text-xs text-zinc-500 block mb-1">Recommendation</span>
                <p className="text-xs text-zinc-300 leading-relaxed">{activeData.hotspot.recommendation}</p>
              </div>
            </div>
          ) : (
            <p className="text-xs text-zinc-500 text-center py-12">No connection hotspots identified.</p>
          )}
        </div>

        {/* SECTION 4: CONNECTION EVENTS (Grid Span 8) */}
        <div className="lg:col-span-8 bg-[#121215] border border-[#1f1f23] rounded p-6 flex flex-col h-[500px]">
          <h2 className="text-xs font-bold text-zinc-500 uppercase tracking-widest mb-6 flex items-center gap-2">
            <Terminal className="w-3.5 h-3.5" /> Connection Events
          </h2>
          <div className="flex-1 overflow-y-auto space-y-2 pr-2 text-xs font-mono">
            {activeData?.events.map((evt, idx) => (
              <div 
                key={`${evt.client}-${evt.server}-${idx}`} 
                className={`p-2.5 border-l-2 bg-[#141416]/60 border border-[#1f1f23] flex flex-col md:flex-row md:items-center justify-between gap-2 transition ${
                  evt.classification === "SHORT_LIVED" ? "border-l-red-500" :
                  evt.classification === "IDLE_PATTERN" ? "border-l-amber-500" :
                  evt.classification === "CHATTER" ? "border-l-blue-500" :
                  evt.classification === "HEAVY" ? "border-l-purple-500" : "border-l-emerald-500"
                }`}
              >
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-bold text-white">{evt.client}</span>
                    <span className="text-zinc-600">➔</span>
                    <span className="text-zinc-400">{evt.server}</span>
                    <span className="text-[10px] text-zinc-500 bg-zinc-800/40 px-1.5 py-0.5 rounded border border-zinc-800">
                      {evt.process} (PID {evt.pid})
                    </span>
                  </div>
                  <div className="flex flex-wrap items-center gap-x-4 text-[10px] text-zinc-500">
                    <div>Duration: <span className="text-zinc-400 font-bold">{evt.duration.toFixed(3)}s</span></div>
                    <div>Packets: <span className="text-zinc-400">{evt.packets}</span></div>
                    <div>Bytes: <span className="text-zinc-400">{evt.bytes.toLocaleString()} B</span></div>
                  </div>
                </div>
                <div className="flex items-center gap-2 self-start md:self-center shrink-0">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    evt.classification === "SHORT_LIVED" ? "bg-red-950/40 text-red-400 border border-red-900/30" :
                    evt.classification === "IDLE_PATTERN" ? "bg-amber-950/40 text-amber-400 border border-amber-900/30" :
                    "bg-zinc-800/40 text-zinc-400 border border-zinc-700/30"
                  }`}>
                    {evt.classification}
                  </span>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-bold ${
                    evt.status === "active" ? "bg-blue-950/40 text-blue-400 border border-blue-900/30 animate-pulse" : "bg-zinc-800/30 text-zinc-500"
                  }`}>
                    {evt.status}
                  </span>
                </div>
              </div>
            ))}
            {activeData?.events.length === 0 && (
              <p className="text-zinc-600 text-center py-24">Waiting for connection events...</p>
            )}
          </div>
        </div>

      </main>
    </div>
  );
}
