import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import SimulationJobPanel from './SimulationJobPanel'
import InvestigationReport from './InvestigationReport'

type Asset = { id: string; name: string }
type Snapshot = { id: string; version: number }
export type SimulationEvent = { id: string; timestamp_seconds: number; source_asset_id: string; target_asset_id: string; event_type: string; transition_id: string | null; result: string; detected: boolean; severity: number }
type Run = { id: string; seed: number; summary: { result: string; successful_transitions: number; detected_attempts: number }; events?: SimulationEvent[] }
type Props = { environmentID: string; snapshots: Snapshot[]; canEdit: boolean; onEventChange: (event: SimulationEvent | null) => void }
async function api<T>(url: string, options?: RequestInit): Promise<T> { const response = await fetch(url, options); const data = await response.json(); if (!response.ok) throw new Error(data.error?.message || 'Request failed'); return data }

export default function SimulationLab({ environmentID, snapshots, canEdit, onEventChange }: Props) {
  const client = useQueryClient()
  const base = `/api/v1/environments/${environmentID}`
  const [snapshotID, setSnapshotID] = useState('')
  const [start, setStart] = useState('')
  const [target, setTarget] = useState('')
  const [seed, setSeed] = useState('42')
  const [duration, setDuration] = useState('300')
  const [maxSteps, setMaxSteps] = useState('12')
  const [detection, setDetection] = useState('25')
  const [control, setControl] = useState('0')
  const [capability, setCapability] = useState('foothold')
  const [runID, setRunID] = useState('')
  const [step, setStep] = useState(0)
  const [playing, setPlaying] = useState(false)
  const [speed, setSpeed] = useState(1)
  const snapshot = useQuery({ queryKey: ['simulation-snapshot', environmentID, snapshotID], enabled: !!snapshotID, queryFn: () => api<{ graph: { assets: Asset[] } }>(`${base}/snapshots/${snapshotID}`) })
  const runs = useQuery({ queryKey: ['simulations', environmentID], queryFn: () => api<Run[]>(`${base}/simulations`) })
  const run = useQuery({ queryKey: ['simulation', environmentID, runID], enabled: !!runID, queryFn: () => api<Run>(`${base}/simulations/${runID}`) })
  const choices = snapshot.data?.graph.assets || []
  const from = choices.some(asset => asset.id === start) ? start : choices[0]?.id || ''
  const to = choices.some(asset => asset.id === target) ? target : choices.find(asset => asset.id !== from)?.id || ''
  const create = useMutation({ mutationFn: () => api<Run>(`${base}/simulations`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ snapshot_id: snapshotID, start_asset_id: from, target_asset_id: to, seed: Number(seed), duration_seconds: Number(duration), max_steps: Number(maxSteps), initial_capabilities: capability === 'foothold' ? ['foothold'] : ['foothold', capability], detection_coverage: Number(detection) / 100, control_effectiveness: Number(control) / 100 }) }), onSuccess: item => { setPlaying(false); setRunID(item.id); setStep(0); void client.invalidateQueries({ queryKey: ['simulations', environmentID] }) } })
  const events = run.data?.events || []
  const event = events[step]
  useEffect(() => { onEventChange(event || null) }, [event?.id, onEventChange])
  useEffect(() => {
    if (!playing || !event) return
    if (step >= events.length - 1) { setPlaying(false); return }
    const next = events[step + 1]
    const delay = Math.max(250, Math.min(3000, (next.timestamp_seconds - event.timestamp_seconds) * 100 / speed))
    const timer = window.setTimeout(() => setStep(value => value + 1), delay)
    return () => window.clearTimeout(timer)
  }, [playing, step, speed, event?.id, run.data?.id])
  function selectRun(id: string) { setPlaying(false); setRunID(id); setStep(0); onEventChange(null) }
  function move(delta: number) { setPlaying(false); setStep(value => Math.max(0, Math.min(events.length - 1, value + delta))) }
  return <section className="path-panel simulation-lab" id="simulation-panel"><div className="path-heading"><div><div className="eyebrow">SYNTHETIC EVENT MODEL</div><h2>Simulation lab</h2><p>Run a seeded scenario against an immutable snapshot, then step through its recorded events.</p></div></div>
    <div className="path-form"><label>SNAPSHOT<select value={snapshotID} onChange={e => { setSnapshotID(e.target.value); setStart(''); setTarget('') }}><option value="">Select snapshot</option>{snapshots.map(item => <option value={item.id} key={item.id}>Version {item.version}</option>)}</select></label><label>START<select value={from} onChange={e => setStart(e.target.value)}>{choices.map(asset => <option value={asset.id} key={asset.id}>{asset.name}</option>)}</select></label><label>TARGET<select value={to} onChange={e => setTarget(e.target.value)}>{choices.map(asset => <option value={asset.id} key={asset.id}>{asset.name}</option>)}</select></label><label>INITIAL ACCESS<select value={capability} onChange={e => setCapability(e.target.value)}><option value="foothold">Asset foothold</option><option value="identity">Identity context</option><option value="operator">Application operator</option><option value="service_identity">Service identity</option></select></label><label>SEED<input aria-label="Simulation seed" type="number" value={seed} onChange={e => setSeed(e.target.value)} /></label><label>DURATION SECONDS<input aria-label="Duration seconds" type="number" min="10" max="3600" value={duration} onChange={e => setDuration(e.target.value)} /></label><label>MAX STEPS<input aria-label="Maximum steps" type="number" min="1" max="50" value={maxSteps} onChange={e => setMaxSteps(e.target.value)} /></label><label>DETECTION COVERAGE %<input aria-label="Detection coverage" type="number" min="0" max="100" value={detection} onChange={e => setDetection(e.target.value)} /></label><label>CONTROL EFFECTIVENESS %<input aria-label="Control effectiveness" type="number" min="0" max="100" value={control} onChange={e => setControl(e.target.value)} /></label>{canEdit && <button className="primary" disabled={!snapshotID || !from || !to || from === to || !seed || create.isPending} onClick={() => create.mutate()}>{create.isPending ? 'Running…' : 'Run simulation'}</button>}</div>
    {create.isError && <div className="result-error" role="alert">{create.error.message}</div>}
    {run.data && <SimulationJobPanel key={run.data.id} environmentID={environmentID} runID={run.data.id} canEdit={canEdit} onEventChange={onEventChange} />}
    {run.data && <InvestigationReport key={`report-${run.data.id}`} environmentID={environmentID} runID={run.data.id} />}
    <div className="results"><div className="results-top"><strong>Run history</strong><span>Latest 50 completed runs</span></div>{runs.isPending ? <p>Loading runs…</p> : runs.isError ? <p role="alert">Could not load runs. <button onClick={() => void runs.refetch()}>Retry</button></p> : runs.data?.length ? <div className="path-tabs">{runs.data.map(item => <button key={item.id} className={runID === item.id ? 'active' : ''} onClick={() => selectRun(item.id)}>#{item.id.slice(-8)} <span>{item.summary.result.replaceAll('_', ' ')}</span></button>)}</div> : <p className="empty-note">No runs yet. Save a snapshot, then start a simulation.</p>}{run.isError && <p role="alert">Could not load run. <button onClick={() => void run.refetch()}>Retry</button></p>}{run.data && <><p>Seed {run.data.seed} · {run.data.summary.successful_transitions} successful transitions · {run.data.summary.detected_attempts} detected attempts</p><div className="playback-controls" role="group" aria-label="Historical event playback"><button disabled={step === 0} onClick={() => { setPlaying(false); setStep(0) }}>Restart</button><button disabled={step === 0} onClick={() => move(-1)}>Previous event</button><button disabled={events.length < 2} onClick={() => { if (step >= events.length - 1) setStep(0); setPlaying(value => !value) }}>{playing ? 'Pause' : 'Play'}</button><button disabled={step >= events.length - 1} onClick={() => move(1)}>Next event</button><label>Speed<select aria-label="Playback speed" value={speed} onChange={e => setSpeed(Number(e.target.value))}><option value="0.5">0.5×</option><option value="1">1×</option><option value="2">2×</option><option value="4">4×</option></select></label><span aria-live="polite">{events.length ? `Event ${step + 1} of ${events.length}` : 'No events'}</span></div>{event && <div className="path-step"><span className="step-number">{String(step + 1).padStart(2, '0')}</span><div><strong>{event.event_type.replaceAll('_', ' ')} · {event.result}</strong><p>{event.source_asset_id} → {event.target_asset_id} at +{event.timestamp_seconds}s</p><small>{event.transition_id || 'Scenario event'} · {event.detected ? 'Detected' : 'Not detected'}</small></div></div>}</>}</div>
  </section>
}
