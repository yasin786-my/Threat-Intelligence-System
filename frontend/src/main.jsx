import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import { io } from 'socket.io-client';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale, LinearScale, PointElement, LineElement,
  ArcElement, Tooltip, Legend, Filler,
} from 'chart.js';
import {
  Activity, ShieldAlert, ShieldCheck, Lock, LogOut,
  Download, Search, Settings as SettingsIcon, BarChart3,
  User, AlertTriangle,
} from 'lucide-react';
import './style.css';

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement,
  ArcElement, Tooltip, Legend, Filler,
);

const api = axios.create({ baseURL: '/api' });

/* ── Chart theme options (Vercel-light) ─────────────── */
const chartFont = {
  family: "'Inter', system-ui, sans-serif",
  size: 11,
  weight: '400',
};
const gridColor = '#ebebeb';
const tickColor = '#888888';

const lineOpts = {
  responsive: true,
  maintainAspectRatio: false,
  interaction: { intersect: false, mode: 'index' },
  plugins: {
    legend: {
      position: 'top', align: 'end',
      labels: { color: '#4d4d4d', font: chartFont, boxWidth: 10, padding: 16, usePointStyle: true },
    },
    tooltip: {
      backgroundColor: '#171717', titleColor: '#fff', bodyColor: '#fff',
      cornerRadius: 6, padding: 10, titleFont: { ...chartFont, weight: '600' },
    },
  },
  scales: {
    x: {
      grid: { display: false },
      ticks: { color: tickColor, font: chartFont },
      border: { color: gridColor },
    },
    y: {
      grid: { color: gridColor, lineWidth: 1 },
      ticks: { color: tickColor, font: chartFont },
      border: { display: false },
    },
  },
};

const doughnutOpts = {
  responsive: true,
  maintainAspectRatio: false,
  cutout: '72%',
  plugins: {
    legend: {
      position: 'bottom',
      labels: { color: '#4d4d4d', font: chartFont, padding: 16, boxWidth: 10, usePointStyle: true },
    },
    tooltip: {
      backgroundColor: '#171717', titleColor: '#fff', bodyColor: '#fff',
      cornerRadius: 6, padding: 10,
    },
  },
};


/* ═══════════════════════════════════════════════════════
   SMALL COMPONENTS
   ═══════════════════════════════════════════════════════ */

function Badge({ value }) {
  const v = (value || '').toLowerCase();
  let cls = 'badge ';
  if (v === 'low' || v === 'normal') cls += 'badge-normal';
  else if (v === 'medium') cls += 'badge-medium';
  else if (v === 'high') cls += 'badge-high';
  else if (v === 'critical') cls += 'badge-critical';
  else if (v === 'active') cls += 'badge-active';
  else if (v === 'unblocked') cls += 'badge-unblocked';
  else if (v === 'expired') cls += 'badge-expired';
  else cls += 'badge-low';
  return <span className={cls}>{value}</span>;
}

function StatCard({ label, value, icon: Icon, tone = 'default' }) {
  return (
    <div className={`stat-card stat-card--${tone}`}>
      <div>
        <div className="stat-label">{label}</div>
        <div className="stat-value">{value ?? '—'}</div>
      </div>
      <div className="stat-icon"><Icon /></div>
    </div>
  );
}

function Alerts({ rows }) {
  return (
    <div>
      {rows.map((x, i) => (
        <div className="alert-row" key={i}>
          <Badge value={x.threat_level} />
          <span className="alert-msg">{x.message}</span>
          <span className="alert-time">
            {new Date(x.timestamp || x.created_at).toLocaleTimeString()}
          </span>
        </div>
      ))}
      {rows.length === 0 && (
        <p className="body-sm text-mute" style={{ padding: '24px 0', textAlign: 'center' }}>
          No recent alerts.
        </p>
      )}
    </div>
  );
}

function TrafficTable({ rows, q, setQ }) {
  return (
    <div className="panel panel-flush">
      <div className="table-header" style={{ padding: 'var(--sp-lg) var(--sp-lg) 0' }}>
        <h3 style={{ margin: 0 }}>Network events</h3>
        <div className="search-bar">
          <Search />
          <input
            placeholder="Search IP, attack, protocol…"
            value={q}
            onChange={e => setQ(e.target.value)}
          />
        </div>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Protocol</th>
              <th>Port</th>
              <th>Size</th>
              <th>Status</th>
              <th>Attack type</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                  {new Date(r.timestamp).toLocaleTimeString()}
                </td>
                <td><code>{r.source_ip}</code></td>
                <td>{r.protocol}</td>
                <td>{r.destination_port}</td>
                <td>{r.packet_size}B</td>
                <td><Badge value={r.status === 'normal' ? 'Normal' : 'High'} /></td>
                <td>{r.attack_type}</td>
                <td>
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '12px',
                    color: r.confidence > 0.8 ? 'var(--error)' : 'var(--ink)',
                  }}>
                    {Math.round(r.confidence * 100)}%
                  </span>
                </td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr>
                <td colSpan="8" style={{ textAlign: 'center', color: 'var(--mute)', padding: '32px' }}>
                  No matching events.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   LOGIN PAGE
   ═══════════════════════════════════════════════════════ */

function Login({ onLogin }) {
  const [u, setU] = useState('admin');
  const [p, setP] = useState('admin123');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function go(e) {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const r = await api.post('/auth/login', { username: u, password: p });
      onLogin(r.data);
    } catch {
      setError('Invalid credentials. Try admin / admin123.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-page">
      <div className="login-card">
        <div className="login-brand">
          <ShieldCheck /> THREAD<span>INTEL</span>
        </div>
        <h1>Security operations center.</h1>
        <p className="login-sub">
          Network intelligence, automated response, and live threat analytics.
        </p>
        <form onSubmit={go}>
          <div className="form-group">
            <label className="form-label" htmlFor="login-user">Username</label>
            <input
              id="login-user"
              className="form-input"
              value={u}
              onChange={e => setU(e.target.value)}
              autoComplete="username"
            />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="login-pass">Password</label>
            <input
              id="login-pass"
              className="form-input"
              type="password"
              value={p}
              onChange={e => setP(e.target.value)}
              autoComplete="current-password"
            />
          </div>
          {error && <div className="login-error">{error}</div>}
          <button className="btn-primary" type="submit" disabled={loading} style={{ width: '100%' }}>
            {loading ? 'Authenticating…' : 'Access dashboard'}
          </button>
          <p className="login-hint">
            Demo: admin / admin123 · viewer / viewer123
          </p>
        </form>
      </div>
    </main>
  );
}


/* ═══════════════════════════════════════════════════════
   PAGES
   ═══════════════════════════════════════════════════════ */

function DashboardPage({ data }) {
  if (!data) return null;

  const trend = {
    labels: data.traffic_trend?.map(x => x.time) || [],
    datasets: [
      {
        label: 'Packets',
        data: data.traffic_trend?.map(x => x.packets) || [],
        borderColor: '#007cf0',
        backgroundColor: 'rgba(0,124,240,0.06)',
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
      },
      {
        label: 'Threats',
        data: data.traffic_trend?.map(x => x.attacks) || [],
        borderColor: '#ee0000',
        backgroundColor: 'rgba(238,0,0,0.04)',
        fill: true,
        tension: 0.35,
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 4,
      },
    ],
  };

  const dist = {
    labels: Object.keys(data.attack_distribution || {}),
    datasets: [{
      data: Object.values(data.attack_distribution || {}),
      backgroundColor: ['#007cf0', '#7928ca', '#ff0080', '#f5a623', '#50e3c2', '#ff4d4d'],
      borderWidth: 0,
      hoverOffset: 4,
    }],
  };

  const scoreColor = (data.severity_score || 0) > 60 ? 'var(--error)' : 'var(--warning)';

  return (
    <>
      <section className="stat-grid">
        <StatCard label="Total packets" value={data.overview?.total_packets} icon={Activity} tone="default" />
        <StatCard label="Normal traffic" value={data.overview?.normal_traffic} icon={ShieldCheck} tone="success" />
        <StatCard label="Suspicious" value={data.overview?.suspicious_traffic} icon={ShieldAlert} tone="warning" />
        <StatCard label="Blocked IPs" value={data.overview?.blocked_ips} icon={Lock} tone="danger" />
      </section>

      <div className="content-grid">
        <div className="panel">
          <h3>Live traffic activity</h3>
          <div className="chart-wrap" style={{ height: 260 }}>
            <Line data={trend} options={lineOpts} />
          </div>
        </div>

        <div className="panel">
          <h3>Attack distribution</h3>
          <div className="chart-wrap" style={{ height: 260 }}>
            <Doughnut data={dist} options={doughnutOpts} />
          </div>
        </div>

        <div className="panel">
          <h3>Recent alerts</h3>
          <Alerts rows={data.recent_alerts || []} />
        </div>

        <div className="panel score-card">
          <h3 style={{ alignSelf: 'stretch' }}>Threat score</h3>
          <div className="score-value" style={{ color: scoreColor }}>
            {data.severity_score || 0}<small>/100</small>
          </div>
          <p className="score-label">Aggregated exposure score</p>
        </div>
      </div>
    </>
  );
}

function BlockedIPsPage({ blocks, session, unblock }) {
  return (
    <div className="panel panel-flush">
      <h3 style={{ padding: 'var(--sp-lg) var(--sp-lg) 0' }}>Application-level block list</h3>
      <div style={{ overflowX: 'auto' }}>
        <table>
          <thead>
            <tr>
              <th>IP address</th>
              <th>Attack</th>
              <th>Level</th>
              <th>Confidence</th>
              <th>Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {blocks.map((b) => (
              <tr key={b.ip + b.blocked_at}>
                <td><code>{b.ip}</code></td>
                <td>{b.attack_type}</td>
                <td><Badge value={b.threat_level} /></td>
                <td>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                    {Math.round(b.confidence * 100)}%
                  </span>
                </td>
                <td><Badge value={b.status} /></td>
                <td>
                  {b.status === 'active' && session.user.role === 'admin' && (
                    <button className="btn-danger btn-sm" onClick={() => unblock(b.ip)}>
                      Unblock
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {blocks.length === 0 && (
              <tr>
                <td colSpan="6" style={{ textAlign: 'center', color: 'var(--mute)', padding: '32px' }}>
                  No blocked IPs.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ThreatIntelPage({ data }) {
  if (!data) return null;
  const maxEvents = Math.max(...(data.top_attacking_ips || []).map(([, n]) => n), 1);

  return (
    <div className="content-grid">
      <div className="panel">
        <h3>Top attacking IPs</h3>
        {(data.top_attacking_ips || []).map(([ip, n]) => (
          <div className="rank-row" key={ip}>
            <code>{ip}</code>
            <div className="rank-bar" style={{ width: `${(n / maxEvents) * 100}%`, minWidth: 16 }} />
            <span className="rank-count">{n} events</span>
          </div>
        ))}
        {(!data.top_attacking_ips || data.top_attacking_ips.length === 0) && (
          <p className="body-sm text-mute" style={{ padding: '24px 0', textAlign: 'center' }}>
            No attack data yet.
          </p>
        )}
      </div>

      <div className="panel">
        <h3>ML model quality</h3>
        {Object.entries(data.model || {}).map(([k, v]) => (
          <div className="metric-row" key={k}>
            <span>{k.replace('_', ' ')}</span>
            <b>{typeof v === 'number' ? v + '%' : v}</b>
          </div>
        ))}
      </div>
    </div>
  );
}

function SettingsPage({ settings, setSettings, saveSettings }) {
  return (
    <div className="panel settings-panel">
      <h3>Detection policy</h3>
      <div className="settings-group">
        <label>
          Auto-block confidence threshold
          <output>{Math.round(settings.confidence_threshold * 100)}%</output>
        </label>
        <input
          type="range" min="0.5" max="0.99" step="0.01"
          value={settings.confidence_threshold}
          onChange={e => setSettings({ ...settings, confidence_threshold: e.target.value })}
        />
      </div>
      <div className="settings-group">
        <label htmlFor="block-duration">Block duration (minutes)</label>
        <input
          id="block-duration"
          type="number"
          value={settings.block_duration_minutes}
          onChange={e => setSettings({ ...settings, block_duration_minutes: e.target.value })}
        />
      </div>
      <button className="btn-primary" onClick={saveSettings}>
        Save policy
      </button>
    </div>
  );
}

function ProfilePage({ session }) {
  return (
    <div className="panel" style={{ maxWidth: 480 }}>
      <h3>Profile</h3>
      <p className="body-md" style={{ marginBottom: 'var(--sp-md)' }}>
        Signed in as <strong>{session.user.username}</strong> with <strong>{session.user.role}</strong> access.
      </p>
      <button
        className="export-link"
        onClick={async () => {
          try {
            const r = await api.get('/reports/csv', { responseType: 'blob' });
            const blob = new Blob([r.data], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'traffic-report.csv';
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
          } catch (err) {
            const msg = err?.response?.data?.error || err.message || 'Export failed';
            alert('Export failed: ' + msg);
          }
        }}
      >
        <Download /> Export traffic CSV
      </button>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   APP SHELL
   ═══════════════════════════════════════════════════════ */

const NAV_ITEMS = [
  { key: 'Dashboard', icon: Activity },
  { key: 'Traffic Monitor', icon: BarChart3 },
  { key: 'Attack Logs', icon: AlertTriangle },
  { key: 'Blocked IPs', icon: Lock },
  { key: 'Threat Intelligence', icon: ShieldAlert },
  { key: 'Settings', icon: SettingsIcon },
  { key: 'Profile', icon: User },
];

function App() {
  const [session, setSession] = useState(
    () => JSON.parse(localStorage.getItem('tis-session') || 'null'),
  );
  const [page, setPage] = useState('Dashboard');
  const [data, setData] = useState(null);
  const [traffic, setTraffic] = useState([]);
  const [blocks, setBlocks] = useState([]);
  const [q, setQ] = useState('');
  const [notice, setNotice] = useState('');
  const [settings, setSettings] = useState({
    confidence_threshold: 0.8,
    block_duration_minutes: 30,
  });

  function login(x) {
    localStorage.setItem('tis-session', JSON.stringify(x));
    setSession(x);
  }

  /* ── Data loading + Socket.IO ────────────────────── */
  useEffect(() => {
    if (!session) return;
    api.defaults.headers.common.Authorization = 'Bearer ' + session.token;
    let stopped = false;
    let timer;

    async function load() {
      const [d, t, b, s] = await Promise.all([
        api.get('/dashboard'), api.get('/traffic'),
        api.get('/blocked-ips'), api.get('/settings'),
      ]);
      if (!stopped) {
        setData(d.data); setTraffic(t.data);
        setBlocks(b.data); setSettings(s.data);
      }
    }

    function refresh() {
      clearTimeout(timer);
      timer = setTimeout(() => load().catch(() => setNotice('Connection to API unavailable')), 150);
    }

    load().catch(() => setNotice('Connection to API unavailable'));

    const sock = io();
    sock.on('traffic', (p) => { setTraffic(x => [p, ...x].slice(0, 200)); refresh(); });
    sock.on('alert', (a) => { setNotice(a.message); setTimeout(() => setNotice(''), 5000); refresh(); });
    sock.on('ip_blocked', (b) => { setBlocks(x => [b, ...x]); refresh(); });

    return () => { stopped = true; clearTimeout(timer); sock.close(); };
  }, [session]);

  /* ── Auth gate ───────────────────────────────────── */
  if (!session) return <Login onLogin={login} />;

  const filtered = traffic.filter(
    x => JSON.stringify(x).toLowerCase().includes(q.toLowerCase()),
  );

  async function unblock(ip) {
    await api.post('/unblock-ip', { ip });
    setBlocks(x => x.map(b => (b.ip === ip ? { ...b, status: 'unblocked' } : b)));
  }

  async function saveSettings() {
    await api.put('/settings', settings);
    setNotice('Policy settings saved');
    setTimeout(() => setNotice(''), 3000);
  }

  /* ── Render ──────────────────────────────────────── */
  return (
    <div className="shell">
      {/* Mobile nav (visible < 600px) */}
      <nav className="mobile-nav" style={{ display: 'none' }}>
        {NAV_ITEMS.map(({ key }) => (
          <button
            key={key}
            className={`mobile-nav-btn${page === key ? ' active' : ''}`}
            onClick={() => setPage(key)}
          >
            {key}
          </button>
        ))}
      </nav>

      {/* Sidebar (desktop) */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <ShieldCheck />
          <span className="brand-text">THREAD<span>INTEL</span></span>
        </div>

        <div className="sidebar-user">
          <b>{session.user.username}</b>
          <small>{session.user.role}</small>
        </div>

        <div className="sidebar-nav">
          {NAV_ITEMS.map(({ key, icon: Icon }) => (
            <button
              key={key}
              className={`sidebar-link${page === key ? ' active' : ''}`}
              onClick={() => setPage(key)}
            >
              <Icon />
              <span className="link-text">{key}</span>
            </button>
          ))}
        </div>

        <div className="sidebar-logout">
          <button
            className="sidebar-link"
            onClick={() => { localStorage.removeItem('tis-session'); setSession(null); }}
          >
            <LogOut />
            <span className="link-text">Sign out</span>
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="main">
        <div className="main-header">
          <div>
            <p className="eyebrow">Live security intelligence</p>
            <h1>{page}</h1>
          </div>
          <div className="health-indicator">
            <span className="health-dot" />
            System healthy
          </div>
        </div>

        {notice && <div className="toast">{notice}</div>}

        {page === 'Dashboard' && <DashboardPage data={data} />}

        {page === 'Traffic Monitor' && (
          <TrafficTable rows={filtered} q={q} setQ={setQ} />
        )}

        {page === 'Attack Logs' && (
          <TrafficTable
            rows={filtered.filter(x => (x.attack_type ?? x.prediction) !== 'Normal')}
            q={q} setQ={setQ}
          />
        )}

        {page === 'Blocked IPs' && (
          <BlockedIPsPage blocks={blocks} session={session} unblock={unblock} />
        )}

        {page === 'Threat Intelligence' && <ThreatIntelPage data={data} />}

        {page === 'Settings' && (
          <SettingsPage
            settings={settings}
            setSettings={setSettings}
            saveSettings={saveSettings}
          />
        )}

        {page === 'Profile' && <ProfilePage session={session} />}
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);
