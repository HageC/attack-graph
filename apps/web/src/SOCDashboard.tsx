import { useQuery } from '@tanstack/react-query'

type Count = { name: string; count: number }
type Summary = { telemetry_events: number; adversarial_events: number; detected_adversarial: number; alerts: number; active_rules: number; events_by_type: Count[]; alerts_by_severity: Count[] }

export default function SOCDashboard({ environmentID }: { environmentID: string }) {
  const summary = useQuery({ queryKey: ['soc-summary', environmentID], queryFn: async ({ signal }) => {
    const response = await fetch(`/api/v1/environments/${environmentID}/soc/summary`, { signal })
    if (!response.ok) throw new Error('Could not load SOC summary')
    return response.json() as Promise<Summary>
  }, refetchInterval: 3000 })
  const data = summary.data
  const coverage = data?.adversarial_events ? Math.round(data.detected_adversarial / data.adversarial_events * 100) : null
  const max = Math.max(1, ...(data?.events_by_type.map(item => item.count) || []))
  return <section className="path-panel soc-dashboard" id="soc-dashboard"><div className="path-heading"><div><div className="eyebrow">DELIVERED SYNTHETIC SIGNALS</div><h2>SOC overview</h2><p>Counts reflect telemetry delivered by backend jobs in this environment.</p></div></div>
    {summary.isPending ? <p className="empty-note">Loading SOC summary…</p> : summary.isError ? <p role="alert" className="result-error">Could not load SOC summary. <button onClick={() => void summary.refetch()}>Retry</button></p> : data && <><div className="soc-metrics"><div><span>Events</span><strong>{data.telemetry_events}</strong></div><div><span>Alerts</span><strong>{data.alerts}</strong></div><div><span>Active rules</span><strong>{data.active_rules}</strong></div><div><span>Detected adversarial events</span><strong>{coverage === null ? '—' : `${coverage}%`}</strong><small>{data.detected_adversarial} of {data.adversarial_events}</small></div></div><div className="soc-breakdown"><div><h3>Events by type</h3>{data.events_by_type.length ? data.events_by_type.map(item => <div className="soc-bar" key={item.name}><span>{item.name.replaceAll('_', ' ')}</span><div><i style={{ width: `${item.count / max * 100}%` }} /></div><strong>{item.count}</strong></div>) : <p className="empty-note">No delivered events yet.</p>}</div><div><h3>Alerts by severity</h3>{data.alerts_by_severity.length ? data.alerts_by_severity.map(item => <p key={item.name}>Severity {item.name}: <strong>{item.count}</strong></p>) : <p className="empty-note">No alerts yet.</p>}</div></div><p className="quiet">Detection coverage is an observed fraction of labeled synthetic adversarial events, not a real-world detection rate.</p></>}
  </section>
}
