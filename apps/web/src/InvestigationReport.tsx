import { useQuery } from '@tanstack/react-query'

type Alert = { id: string; rule_name: string; event_type: string; asset_id: string; severity: number }
type Report = { schema_version: number; run_id: string; snapshot_id: string; snapshot_hash: string; seed: number; summary: { result: string; successful_transitions: number; detected_attempts: number }; events: { id: string; event_type: string; timestamp_seconds: number; result: string }[]; delivered_events: number; alert_count: number; alerts: Alert[]; evidence_limit: number; caveat: string }

export default function InvestigationReport({ environmentID, runID }: { environmentID: string; runID: string }) {
  const report = useQuery({ queryKey: ['investigation-report', environmentID, runID], queryFn: async ({ signal }) => {
    const response = await fetch(`/api/v1/environments/${environmentID}/reports/${runID}`, { signal })
    if (!response.ok) throw new Error('Could not load investigation report')
    const data = await response.json() as Report
    if (!Array.isArray(data.events) || !Array.isArray(data.alerts) || !data.summary || typeof data.snapshot_hash !== 'string') throw new Error('Invalid investigation report')
    return data
  }, refetchInterval: 3000 })
  function exportJSON() {
    if (!report.data) return
    const blob = new Blob([JSON.stringify(report.data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `attackgraph-report-${runID}.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }
  return <div className="results investigation-report"><div className="results-top"><strong>Investigation report</strong><button disabled={!report.data} onClick={exportJSON}>Export JSON</button></div>
    {report.isPending ? <p>Loading report…</p> : report.isError ? <p role="alert">Could not load report. <button onClick={() => void report.refetch()}>Retry</button></p> : report.data && <><p>Snapshot {report.data.snapshot_id} · Seed {report.data.seed} · {report.data.summary.result.replaceAll('_', ' ')}</p><p>{report.data.delivered_events} delivered events · {report.data.alert_count} rule alerts · {report.data.summary.detected_attempts} simulated detections</p><details><summary>Snapshot fingerprint and scenario timeline</summary><p>SHA-256 {report.data.snapshot_hash}</p><ol>{report.data.events.map(event => <li key={event.id}>+{event.timestamp_seconds}s · {event.event_type.replaceAll('_', ' ')} · {event.result}</li>)}</ol></details><h3>Alert evidence</h3>{report.data.alerts.length ? report.data.alerts.map(alert => <p key={alert.id}>{alert.rule_name} · {alert.event_type.replaceAll('_', ' ')} · {alert.asset_id} · severity {alert.severity}</p>) : <p className="empty-note">No rule alerts have been delivered for this run.</p>}{report.data.alert_count > report.data.evidence_limit && <p>Showing first {report.data.evidence_limit} alerts of {report.data.alert_count}.</p>}<p className="quiet">{report.data.caveat}</p></>}
  </div>
}
