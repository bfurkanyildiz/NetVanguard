import React, { useState, useEffect } from 'react';

const Scanner = () => {
    const [activeTab, setActiveTab] = useState('scanner');
    const [email, setEmail] = useState('');
    const [filePath, setFilePath] = useState('');
    const [metadataResults, setMetadataResults] = useState(null);
    const [breachResults, setBreachResults] = useState(null);
    const [snifferLogs, setSnifferLogs] = useState([]);
    const [isSniffing, setIsSniffing] = useState(false);
    const [isBreachLoading, setIsBreachLoading] = useState(false);
    const [error, setError] = useState(null);

    // CSS variables matching index.html EXACTLY
    const btnBase = "flex-1 min-w-[190px] aspect-square flex flex-col items-center justify-center gap-5 p-8 text-[1.15rem] font-extrabold tracking-tight rounded-xl border-2 transition-all duration-500 ease-[cubic-bezier(0.175,0.885,0.32,1.275)] cursor-pointer group";
    
    // Inactive: Faded, grayscale emoji, subtle green border
    const btnInactive = "bg-[#101928]/60 border-[#00ff41]/10 text-[#8abf96]/50 hover:bg-[#111927] hover:border-[#00ff41]/40 hover:text-white hover:-translate-y-2 hover:shadow-[0_20px_40px_rgba(0,0,0,0.4)]";
    
    // Active: Glowing cyan/indigo theme from index.html
    const btnActive = "bg-gradient-to-br from-[#00f2fe]/20 to-[#4f46e5]/20 border-[#00f2fe] text-white shadow-[0_0_30px_rgba(0,242,254,0.3),inset_0_0_15px_rgba(79,70,229,0.2)] scale-[1.05] z-10";

    const extractMetadata = async () => {
        setError(null);
        setMetadataResults(null);
        try {
            const res = await fetch('/api/metadata', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ path: filePath })
            });
            const data = await res.json();
            if (data.success) {
                setMetadataResults(data.data);
            } else {
                setError("HATA: İşlem başarısız!");
            }
        } catch (err) {
            setError("HATA: İşlem başarısız!");
        }
    };

    const checkBreach = async () => {
        if (!email) return;
        setError(null);
        setBreachResults(null);
        setIsBreachLoading(true);
        try {
            const res = await fetch('/api/breach_mock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            const data = await res.json();
            if (data.success) {
                setBreachResults(data);
            } else {
                setError(data.error || "HATA: İşlem başarısız!");
            }
        } catch (err) {
            setError("İstihbarat sunucularına ulaşılamıyor!");
        } finally {
            setIsBreachLoading(false);
        }
    };

    const startSniff = async () => {
        if (isSniffing) {
            setIsSniffing(false);
            return;
        }
        
        setIsSniffing(true);
        setError(null);
        setSnifferLogs(prev => [`[${new Date().toLocaleTimeString()}] Sniffer initialized. Capturing for 5s...`, ...prev]);
        
        try {
            const res = await fetch('/api/sniff');
            const data = await res.json();
            if (data.success) {
                const newLogs = data.packets.map(p => `[${p.proto}] ${p.src} -> ${p.dest} (${p.len}B)`);
                setSnifferLogs(prev => [...newLogs, ...prev]);
            } else {
                setError("HATA: İşlem başarısız!");
                setSnifferLogs(prev => [`[! HATA] ${data.error || 'Capture failed'}`, ...prev]);
            }
        } catch (err) {
            setError("HATA: İşlem başarısız!");
            setSnifferLogs(prev => [`[! HATA] Connection error`, ...prev]);
        } finally {
            setIsSniffing(false);
        }
    };

    return (
        <div className="min-h-screen bg-[#030303] text-[#e0ffe6] font-mono p-12 selection:bg-[#00ff41]/30">
            {/* ═══ NAVIGATION BAR ═══ */}
            <nav className="flex flex-wrap justify-center items-center gap-8 mb-24 max-w-7xl mx-auto">
                <button 
                    onClick={() => setActiveTab('dashboard')}
                    className={`${btnBase} ${activeTab === 'dashboard' ? btnActive : btnInactive}`}
                >
                    <span className={`text-5xl mb-2 transition-all duration-300 ${activeTab === 'dashboard' ? '' : 'grayscale opacity-40 group-hover:grayscale-0 group-hover:opacity-100'}`}>🏠</span>
                    <span className="text-center leading-tight">Kontrol<br/>Paneli</span>
                </button>

                <button 
                    onClick={() => setActiveTab('scanner')}
                    className={`${btnBase} ${activeTab === 'scanner' ? btnActive : btnInactive}`}
                >
                    <span className={`text-5xl mb-2 transition-all duration-300 ${activeTab === 'scanner' ? '' : 'grayscale opacity-40 group-hover:grayscale-0 group-hover:opacity-100'}`}>🔍</span>
                    <span className="text-center leading-tight">Ağ<br/>Tarayıcı</span>
                </button>

                <button 
                    onClick={() => setActiveTab('wifi')}
                    className={`${btnBase} ${activeTab === 'wifi' ? btnActive : btnInactive}`}
                >
                    <span className={`text-5xl mb-2 transition-all duration-300 ${activeTab === 'wifi' ? '' : 'grayscale opacity-40 group-hover:grayscale-0 group-hover:opacity-100'}`}>🛰️</span>
                    <span className="text-center leading-tight">Wi-Fi<br/>Radarı</span>
                </button>

                <button 
                    onClick={() => setActiveTab('intel')}
                    className={`${btnBase} ${activeTab === 'intel' ? btnActive : btnInactive}`}
                >
                    <span className={`text-5xl mb-2 transition-all duration-300 ${activeTab === 'intel' ? '' : 'grayscale opacity-40 group-hover:grayscale-0 group-hover:opacity-100'}`}>🕵️</span>
                    <span className="text-center leading-tight">İstihbarat</span>
                </button>

                <button 
                    onClick={() => setActiveTab('sniffer')}
                    className={`${btnBase} ${activeTab === 'sniffer' ? btnActive : btnInactive}`}
                >
                    <span className={`text-5xl mb-2 transition-all duration-300 ${activeTab === 'sniffer' ? '' : 'grayscale opacity-40 group-hover:grayscale-0 group-hover:opacity-100'}`}>📡</span>
                    <span className="text-center leading-tight">Canlı<br/>Trafik</span>
                </button>
            </nav>

            {/* ═══ TAB CONTENT ═══ */}
            <main className="max-w-6xl mx-auto">
                {activeTab === 'intel' && (
                    <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
                        <section className="bg-[#0a0b10] border border-[#00ff41]/20 rounded-2xl p-10 shadow-[0_20px_50px_rgba(0,0,0,0.5)]">
                            <h2 className="text-2xl font-black text-[#00ff41] mb-8 flex items-center gap-3">
                                <span className="animate-pulse">▶</span> İSTİHBARAT PANELİ (OSINT)
                            </h2>
                            
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                                {/* Metadata Hunter */}
                                <div className="space-y-4">
                                    <label className="block text-sm font-bold text-[#8abf96] uppercase tracking-widest">Görüntü Analizi (EXIF)</label>
                                    <input 
                                        type="text" 
                                        value={filePath}
                                        onChange={(e) => setFilePath(e.target.value)}
                                        placeholder="/path/to/image.jpg"
                                        className="w-full bg-[#050608] border border-[#00ff41]/10 rounded-lg p-4 text-white placeholder:text-white/20 focus:border-[#00ff41] focus:ring-1 focus:ring-[#00ff41] outline-none transition-all"
                                    />
                                    <button 
                                        onClick={extractMetadata}
                                        className="w-full py-3 bg-[#00ff41]/10 border border-[#00ff41]/40 text-[#00ff41] font-bold rounded-lg hover:bg-[#00ff41]/20 transition-all">
                                        METADATA AYRIŞTIR
                                    </button>
                                    
                                    {metadataResults && (
                                        <div className="mt-4 p-4 bg-black/40 border border-[#00ff41]/20 rounded-lg max-h-60 overflow-y-auto text-xs">
                                            {Object.entries(metadataResults).map(([k, v]) => (
                                                <div key={k} className="flex justify-between py-1 border-b border-white/5">
                                                    <span className="text-[#8abf96]">{k}:</span>
                                                    <span className="text-white">{v}</span>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>

                                {/* Breach Scanner */}
                                <div className="space-y-4">
                                    <label className="block text-sm font-bold text-[#8abf96] uppercase tracking-widest">DarkWeb Sızıntı Kontrolü</label>
                                    <input 
                                        type="email" 
                                        value={email}
                                        onChange={(e) => setEmail(e.target.value)}
                                        placeholder="operator@netvanguard.io"
                                        className="w-full bg-[#050608] border border-[#00ff41]/10 rounded-lg p-4 text-white placeholder:text-white/20 focus:border-[#00ff41] focus:ring-1 focus:ring-[#00ff41] outline-none transition-all"
                                    />
                                    <button 
                                        onClick={checkBreach}
                                        disabled={isBreachLoading}
                                        className={`w-full py-3 font-bold rounded-lg transition-all border ${isBreachLoading ? 'bg-gray-800 text-gray-500 border-gray-700' : 'bg-[#00ff41]/10 border-[#00ff41]/40 text-[#00ff41] hover:bg-[#00ff41]/20'}`}>
                                        {isBreachLoading ? 'SORGULANIYOR...' : 'BREACH SORGULA'}
                                    </button>

                                    {breachResults && (
                                        <div className={`mt-4 p-4 rounded-lg border ${breachResults.found ? 'bg-red-900/20 border-red-500/40' : 'bg-green-900/20 border-green-500/40'}`}>
                                            <div className="font-bold mb-2">{breachResults.found ? '⚠️ SIZINTI BULUNDU!' : '✅ TEMİZ'}</div>
                                            <ul className="text-xs space-y-1">
                                                {breachResults.sources.map((src, i) => <li key={i}>• {src}</li>)}
                                            </ul>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </section>
                    </div>
                )}

                {activeTab === 'sniffer' && (
                    <div className="animate-in fade-in zoom-in-95 duration-500">
                        <section className="bg-[#0a0b10] border border-[#ff0055]/20 rounded-2xl p-10 shadow-[0_20px_50px_rgba(0,0,0,0.5)]">
                            <div className="flex justify-between items-center mb-8">
                                <h2 className="text-2xl font-black text-[#ff0055] flex items-center gap-3">
                                    <span className={`w-3 h-3 bg-[#ff0055] rounded-full ${isSniffing ? 'animate-ping' : ''}`}></span> CANLI TRAFİK ANALİZİ
                                </h2>
                                <button 
                                    onClick={startSniff}
                                    disabled={isSniffing}
                                    className={`px-8 py-3 rounded-lg font-black transition-all uppercase tracking-tighter border ${isSniffing ? 'bg-gray-800 text-gray-500 border-gray-700' : 'bg-[#ff0055]/10 border-[#ff0055]/40 text-[#ff0055] hover:bg-[#ff0055]/30'}`}>
                                    {isSniffing ? 'Analiz Yapılıyor...' : 'Trafik Dinlemeyi Başlat'}
                                </button>
                            </div>

                            {/* Terminal Box */}
                            <div className="relative group">
                                <div className="absolute -inset-1 bg-gradient-to-r from-[#ff0055]/20 to-transparent rounded-lg blur opacity-25 group-hover:opacity-50 transition duration-1000"></div>
                                <div className="relative bg-black rounded-lg p-6 h-80 overflow-y-auto border border-white/5 font-mono text-sm scrollbar-thin scrollbar-thumb-[#ff0055]/20">
                                    {error ? (
                                        <div className="text-red-500 font-bold mb-4 animate-pulse">{error}</div>
                                    ) : (
                                        <>
                                            <div className="text-[#ff0055]/60 mb-2">[SYSTEM] PCAP Interface initialized...</div>
                                            <div className="text-[#00ff41]/40 mb-4">[INFO] Waiting for packet stream (5s chunks)...</div>
                                        </>
                                    )}
                                    
                                    <div className="space-y-1">
                                        {snifferLogs.map((log, i) => (
                                            <div key={i} className={`${log.startsWith('[!') ? 'text-red-400' : 'text-white/80'} border-l-2 border-white/5 pl-2`}>
                                                {log}
                                            </div>
                                        ))}
                                        {isSniffing && <div className="text-white/80 animate-pulse">_</div>}
                                    </div>
                                    {/* Scanlines Effect */}
                                    <div className="absolute inset-0 pointer-events-none bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.1)_50%),linear-gradient(90deg,rgba(255,0,0,0.02),rgba(0,255,0,0.01),rgba(0,0,255,0.02))] bg-[length:100%_4px,3px_100%]"></div>
                                </div>
                            </div>
                        </section>
                    </div>
                )}

                {activeTab === 'scanner' && (
                    <div className="text-center py-20 text-[#8abf96]/40 text-xl font-bold italic tracking-widest">
                        NETWORK SCANNER MODULE LOADED
                    </div>
                )}

                {activeTab === 'wifi' && (
                    <div className="text-center py-20 text-[#8abf96]/40 text-xl font-bold italic tracking-widest">
                        WIFI RADAR MODULE READY
                    </div>
                )}
            </main>
        </div>
    );
};

export default Scanner;
