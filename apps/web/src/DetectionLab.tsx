import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'

type Asset = { id: string; name: string }
type Telemetry = { id: string; job_id: string; run_id: string; sequence: number; schema_version: number; occurred_at_seconds: number; event_type: string; asset_id: string; source_asset_id: string; result: string; severity: number; detected: boolean; ground_truth: string; payload: Record<string, unknown>; created_at: string }
type Alert = { id: string; rule_id: string; rule_name: string; job_id: string; telemetry_id: string; event_type: string; asset_id: string; severity: number; created_at: string }
type Rule = { id: string; name: string; enabled: boolean; event_type: string; min_severity: number; asset_id: string }
type TestResult = { rule_id: string; match_count: number; telemetry_ids: string[]; truncated: boolean }
type Props = { environmentID: string; assets: Asset[]; canEdit: boolean }
const eventTypes = ['scenario_started', 'suspicious_access_attempt', 'control_block', 'endpoint_alert', 'sensitive_resource_access', 'simulation_event']

async function api<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options)
  const data = await response.json()
  if (!response.ok) throw new Error(data.error?.message || 'Request failed')
  return data
}

export default function DetectionLab({ environmentID, assets, canEdit }: Props) {
  const client = useQueryClient()
  const base = `/api/v1/environments/${environmentID}`
  const [eventType, setEventType] = useState('')
  const [assetID, setAssetID] = useState('')
  const [runID, setRunID] = useState('')
  const [minimum, setMinimum] = useState('')
  const [search, setSearch] = useState('')
  const [selectedID, setSelectedID] = useState('')
  const [ruleName, setRuleName] = useState('')
  const [ruleType, setRuleType] = useState('endpoint_alert')
  const [ruleSeverity, setRuleSeverity] = useState('3')
  const [ruleAsset, setRuleAsset] = useState('')
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const params = new URLSearchParams({ limit: '200' })
  if (eventType) params.set('event_type', eventType)
  if (assetID) params.set('asset_id', assetID)
  if (runID) params.set('run_id', runID)
  if (minimum) params.set('min_severity', minimum)
  const telemetry = useQuery({ queryKey: ['telemetry', environmentID, params.toString()], queryFn: ({ signal }) => api<Telemetry[]>(`${base}/telemetry?${params}`, { signal }), refetchInterval: 3000 })
  const alerts = useQuery({ queryKey: ['alerts', environmentID], queryFn: ({ signal }) => api<Alert[]>(`${base}/alerts?limit=100`, { signal }), refetchInterval: 3000 })
  const rules = useQuery({ queryKey: ['detection-rules', environmentID], queryFn: ({ signal }) => api<Rule[]>(`${base}/detection-rules`, { signal }) })
  const visible = useMemo(() => (telemetry.data || []).filter(item => `${item.event_type} ${item.asset_id} ${item.source_asset_id} ${item.result} ${item.job_id}`.toLowerCase().includes(search.toLowerCase())), [telemetry.data, search])
  const selected = visible.find(item => item.id === selectedID) || visible[0]
  const create = useMutation({ mutationFn: () => api<Rule>(`${base}/detection-rules`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: ruleName, event_type: ruleType, min_severity: Number(ruleSeverity), asset_id: ruleAsset }) }), onSuccess: () => { setRuleName(''); void client.invalidateQueries({ queryKey: ['detection-rules', environmentID] }) } })
  const toggle = useMutation({ mutationFn: ({ ruleID, enabled }: { ruleID: string; enabled: boolean }) => api<Rule>(`${base}/detection-rules/${ruleID}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }) }), onSuccess: () => void client.invalidateQueries({ queryKey: ['detection-rules', environmentID] }) })
  const test = useMutation({ mutationFn: (ruleID: string) => api<TestResult>(`${base}/detection-rules/${ruleID}/test`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) }), onSuccess: result => setTestResult(result) })

  return <div className="detection-lab">
    <section className="path-panel" id="security-events"><div className="path-heading"><div><div className="eyebrow">DELIVERED SIMULATION TELEMETRY</div><h2>Security events</h2><p>Versioned, synthetic records appear as backend jobs deliver their source events.</p></div></div>
      <div className="detection-filters"><label>EVENT TYPE<select aria-label="Filter event type" value={eventType} onChange={event => setEventType(event.target.value)}><option value="">All types</option>{eventTypes.map(type => <option value={type} key={type}>{type.replaceAll('_', ' ')}</option>)}</select></label><label>ASSET<select aria-label="Filter asset" value={assetID} onChange={event => setAssetID(event.target.value)}><option value="">All assets</option>{assets.map(asset => <option value={asset.id} key={asset.id}>{asset.name}</option>)}</select></label><label>MIN SEVERITY<select aria-label="Filter severity" value={minimum} onChange={event => setMinimum(event.target.value)}><option value="">Any</option>{[1, 2, 3, 4, 5].map(value => <option value={value} key={value}>{value}+</option>)}</select></label><label>RUN ID<input aria-label="Filter run ID" value={runID} onChange={event => setRunID(event.target.value)} placeholder="Optional run ID" /></label><label>SEARCH<input aria-label="Search events" value={search} onChange={event => setSearch(event.target.value)} placeholder="Type, asset, result…" /></label></div>
      {telemetry.isPending ? <p className="empty-note">Loading events…</p> : telemetry.isError ? <p role="alert" className="result-error">Could not load events. <button onClick={() => void telemetry.refetch()}>Retry</button></p> : visible.length ? <div className="event-explorer"><div className="event-list">{visible.map(item => <button key={item.id} className={selected?.id === item.id ? 'active' : ''} onClick={() => setSelectedID(item.id)}><span className={`event-severity severity-${item.severity}`}>{item.severity}</span><span><strong>{item.event_type.replaceAll('_', ' ')}</strong><small>{item.asset_id} · +{item.occurred_at_seconds}s · {item.result}</small></span></button>)}</div><div className="event-detail"><h3>Event detail</h3><dl><div><dt>Asset</dt><dd>{selected?.asset_id}</dd></div><div><dt>Source</dt><dd>{selected?.source_asset_id}</dd></div><div><dt>Run</dt><dd>{selected?.run_id}</dd></div><div><dt>Job</dt><dd>{selected?.job_id}</dd></div><div><dt>Label</dt><dd>{selected?.ground_truth}</dd></div><div><dt>Detected</dt><dd>{selected?.detected ? 'Yes' : 'No'}</dd></div><div><dt>Schema</dt><dd>v{selected?.schema_version}</dd></div></dl><details><summary>Source event</summary><pre>{JSON.stringify(selected?.payload, null, 2)}</pre></details></div></div> : <p className="empty-note">No delivered events match these filters. Start a delivery job or adjust the filters.</p>}
      <p className="quiet">Showing up to 200 latest matching events. Event time is relative to the synthetic scenario.</p>
    </section>
    <section className="path-panel" id="detection-lab"><div className="path-heading"><div><div className="eyebrow">DECLARATIVE MATCHING</div><h2>Detection lab</h2><p>Match event type, minimum severity, and an optional synthetic asset. New alerts are created as events arrive.</p></div></div>
      {canEdit && <div className="detection-filters"><label>RULE NAME<input aria-label="Rule name" value={ruleName} onChange={event => setRuleName(event.target.value)} placeholder="Endpoint alert on identity" /></label><label>EVENT TYPE<select aria-label="Rule event type" value={ruleType} onChange={event => setRuleType(event.target.value)}>{eventTypes.map(type => <option value={type} key={type}>{type.replaceAll('_', ' ')}</option>)}</select></label><label>MIN SEVERITY<select aria-label="Rule minimum severity" value={ruleSeverity} onChange={event => setRuleSeverity(event.target.value)}>{[1, 2, 3, 4, 5].map(value => <option value={value} key={value}>{value}+</option>)}</select></label><label>ASSET<select aria-label="Rule asset" value={ruleAsset} onChange={event => setRuleAsset(event.target.value)}><option value="">Any asset</option>{assets.map(asset => <option value={asset.id} key={asset.id}>{asset.name}</option>)}</select></label><button className="primary" disabled={ruleName.trim().length < 3 || create.isPending} onClick={() => create.mutate()}>{create.isPending ? 'Creating…' : 'Create rule'}</button></div>}
      {create.isError && <p className="result-error" role="alert">{create.error.message}</p>}{toggle.isError && <p className="result-error" role="alert">{toggle.error.message}</p>}{test.isError && <p className="result-error" role="alert">{test.error.message}</p>}
      <div className="detection-columns"><div><h3>Rules</h3>{rules.isPending ? <p className="empty-note">Loading rules…</p> : rules.isError ? <p role="alert" className="result-error">Could not load rules. <button onClick={() => void rules.refetch()}>Retry</button></p> : rules.data?.length ? rules.data.map(rule => <div className="detection-row" key={rule.id}><div><strong>{rule.name}</strong><small>{rule.event_type.replaceAll('_', ' ')} · severity {rule.min_severity}+{rule.asset_id ? ` · ${rule.asset_id}` : ''}</small></div><span className={rule.enabled ? 'rule-enabled' : 'rule-disabled'}>{rule.enabled ? 'Enabled' : 'Disabled'}</span>{canEdit && <><button disabled={toggle.isPending} onClick={() => toggle.mutate({ ruleID: rule.id, enabled: !rule.enabled })}>{rule.enabled ? 'Disable' : 'Enable'}</button><button disabled={test.isPending} onClick={() => test.mutate(rule.id)}>Test history</button></>}</div>) : <p className="empty-note">No rules yet. Create one to evaluate future delivered events.</p>}{testResult && <p role="status" className="quiet">Historical test: {testResult.match_count} matching events{testResult.truncated ? ' (first 100 IDs returned)' : ''}.</p>}</div><div><h3>Alerts</h3>{alerts.isPending ? <p className="empty-note">Loading alerts…</p> : alerts.isError ? <p role="alert" className="result-error">Could not load alerts. <button onClick={() => void alerts.refetch()}>Retry</button></p> : alerts.data?.length ? alerts.data.map(alert => <div className="detection-row" key={alert.id}><span className={`event-severity severity-${alert.severity}`}>{alert.severity}</span><div><strong>{alert.rule_name}</strong><small>{alert.event_type.replaceAll('_', ' ')} · {alert.asset_id}</small></div></div>) : <p className="empty-note">No alerts yet. Enabled rules create alerts when matching events arrive.</p>}</div></div>
    </section>
  </div>
}
