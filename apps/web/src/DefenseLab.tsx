import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'

type Snapshot = { id: string; version: number }
type Asset = { id: string; name: string }
type Rate = { estimate: number; ci95: [number, number] }
type Outcome = { target_reached: Rate; detected_run: Rate; mean_successful_transitions: number; mean_assets_affected: number; mean_elapsed_seconds: number; median_time_to_detection_seconds: number | null; median_time_to_target_seconds: number | null; p95_time_to_target_seconds: number | null }
type Comparison = { iterations: number; seed: number; baseline: Outcome; proposed: Outcome; target_reached_delta: Rate; assumptions: string }
async function api<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options)
  const data = await response.json()
  if (!response.ok) throw new Error(data.error?.message || 'Request failed')
  return data
}
const pct = (value: number) => `${(value * 100).toFixed(1)}%`
const seconds = (value: number | null) => value === null ? '—' : `${value} s`
function RateCell({ rate }: { rate: Rate }) { return <span>{pct(rate.estimate)} <small>95% interval {pct(rate.ci95[0])}–{pct(rate.ci95[1])}</small></span> }

export default function DefenseLab({ environmentID, snapshots, canEdit }: { environmentID: string; snapshots: Snapshot[]; canEdit: boolean }) {
  const base = `/api/v1/environments/${environmentID}`
  const [snapshotID, setSnapshotID] = useState('')
  const [start, setStart] = useState('')
  const [target, setTarget] = useState('')
  const [iterations, setIterations] = useState(200)
  const [seed, setSeed] = useState(42)
  const [baseControl, setBaseControl] = useState(0)
  const [newControl, setNewControl] = useState(50)
  const [baseDetection, setBaseDetection] = useState(25)
  const [newDetection, setNewDetection] = useState(75)
  const snapshot = useQuery({ queryKey: ['defense-snapshot', environmentID, snapshotID], enabled: !!snapshotID, queryFn: () => api<{ graph: { assets: Asset[] } }>(`${base}/snapshots/${snapshotID}`) })
  const assets = snapshot.data?.graph.assets || []
  const from = assets.some(asset => asset.id === start) ? start : assets[0]?.id || ''
  const to = assets.some(asset => asset.id === target) ? target : assets.find(asset => asset.id !== from)?.id || ''
  const compare = useMutation({ mutationFn: () => api<Comparison>(`${base}/defense/compare`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ snapshot_id: snapshotID, start_asset_id: from, target_asset_id: to, seed, duration_seconds: 300, max_steps: 12, initial_capabilities: ['foothold'], detection_coverage: baseDetection / 100, control_effectiveness: baseControl / 100, proposed_detection_coverage: newDetection / 100, proposed_control_effectiveness: newControl / 100, iterations }) }) })
  return <section className="path-panel defense-lab" id="defense-panel"><div className="path-heading"><div><div className="eyebrow">PAIRED MONTE CARLO MODEL</div><h2>Defense comparison</h2><p>Run the same seeded scenarios under baseline and proposed controls. Results describe this synthetic model.</p></div></div>
    <div className="path-form"><label>SNAPSHOT<select value={snapshotID} onChange={e => { setSnapshotID(e.target.value); setStart(''); setTarget('') }}><option value="">Select snapshot</option>{snapshots.map(item => <option key={item.id} value={item.id}>Version {item.version}</option>)}</select></label><label>START<select value={from} onChange={e => setStart(e.target.value)}>{assets.map(asset => <option key={asset.id} value={asset.id}>{asset.name}</option>)}</select></label><label>TARGET<select value={to} onChange={e => setTarget(e.target.value)}>{assets.map(asset => <option key={asset.id} value={asset.id}>{asset.name}</option>)}</select></label><label>RUNS<input aria-label="Monte Carlo iterations" type="number" min="20" max="1000" value={iterations} onChange={e => setIterations(Number(e.target.value))} /></label><label>SEED<input aria-label="Comparison seed" type="number" value={seed} onChange={e => setSeed(Number(e.target.value))} /></label><label>BASE CONTROL %<input type="number" min="0" max="100" value={baseControl} onChange={e => setBaseControl(Number(e.target.value))} /></label><label>PROPOSED CONTROL %<input type="number" min="0" max="100" value={newControl} onChange={e => setNewControl(Number(e.target.value))} /></label><label>BASE DETECTION %<input type="number" min="0" max="100" value={baseDetection} onChange={e => setBaseDetection(Number(e.target.value))} /></label><label>PROPOSED DETECTION %<input type="number" min="0" max="100" value={newDetection} onChange={e => setNewDetection(Number(e.target.value))} /></label>{canEdit && <button className="primary" disabled={!snapshotID || !from || !to || from === to || compare.isPending || iterations < 20 || iterations > 1000 || [baseControl, newControl, baseDetection, newDetection].some(n => n < 0 || n > 100)} onClick={() => compare.mutate()}>{compare.isPending ? 'Comparing…' : 'Compare defenses'}</button>}</div>
    {compare.isError && <p role="alert" className="result-error">{compare.error.message}</p>}
    {compare.data && <div className="results"><div className="results-top"><strong>{compare.data.iterations} paired runs · seed {compare.data.seed}</strong><span>Immutable snapshot</span></div><div className="defense-results"><div><strong>Outcome</strong><strong>Baseline</strong><strong>Proposed</strong></div><div><span>Target reached</span><RateCell rate={compare.data.baseline.target_reached} /><RateCell rate={compare.data.proposed.target_reached} /></div><div><span>Any detection</span><RateCell rate={compare.data.baseline.detected_run} /><RateCell rate={compare.data.proposed.detected_run} /></div><div><span>Mean successful transitions</span><span>{compare.data.baseline.mean_successful_transitions}</span><span>{compare.data.proposed.mean_successful_transitions}</span></div><div><span>Mean assets affected</span><span>{compare.data.baseline.mean_assets_affected}</span><span>{compare.data.proposed.mean_assets_affected}</span></div><div><span>Median time to detection</span><span>{seconds(compare.data.baseline.median_time_to_detection_seconds)}</span><span>{seconds(compare.data.proposed.median_time_to_detection_seconds)}</span></div><div><span>Median time to target</span><span>{seconds(compare.data.baseline.median_time_to_target_seconds)}</span><span>{seconds(compare.data.proposed.median_time_to_target_seconds)}</span></div><div><span>95th percentile time to target</span><span>{seconds(compare.data.baseline.p95_time_to_target_seconds)}</span><span>{seconds(compare.data.proposed.p95_time_to_target_seconds)}</span></div></div><p>Change in target reach: <RateCell rate={compare.data.target_reached_delta} /></p><p className="empty-note">{compare.data.assumptions}</p></div>}
  </section>
}
