import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { SimulationEvent } from './SimulationLab'

type Job = { id: string; run_id: string; status: 'running' | 'paused' | 'stopped' | 'completed'; event_cursor: number; total_events: number; speed: number; updated_at?: string; events?: SimulationEvent[] }
type StreamMessage = { type: 'state'; job: Job } | { type: 'event'; job_id: string; event_cursor: number; event: SimulationEvent; updated_at: string }
type Props = { environmentID: string; runID: string; canEdit: boolean; onEventChange: (event: SimulationEvent | null) => void }

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options)
  const data = await response.json()
  if (!response.ok) throw new Error(data.error?.message || 'Request failed')
  return data
}

export default function SimulationJobPanel({ environmentID, runID, canEdit, onEventChange }: Props) {
  const client = useQueryClient()
  const base = `/api/v1/environments/${environmentID}`
  const [selectedJobID, setSelectedJobID] = useState('')
  const [connection, setConnection] = useState<'connecting' | 'connected' | 'reconnecting' | 'unavailable' | 'finished'>('connecting')
  const jobs = useQuery({ queryKey: ['simulation-jobs', environmentID], queryFn: ({ signal }) => request<Job[]>(`${base}/simulation-jobs`, { signal }) })
  const related = jobs.data?.filter(item => item.run_id === runID) || []
  const jobID = related.some(item => item.id === selectedJobID) ? selectedJobID : related[0]?.id || ''
  const job = useQuery({ queryKey: ['simulation-job', environmentID, jobID], enabled: !!jobID, queryFn: ({ signal }) => request<Job>(`${base}/simulation-jobs/${jobID}`, { signal }), refetchInterval: query => ['running', 'paused'].includes(query.state.data?.status || '') && connection !== 'connected' ? 1000 : false })
  const terminal = job.data?.status === 'completed' || job.data?.status === 'stopped'
  useEffect(() => {
    if (!jobID || terminal) { setConnection(terminal ? 'finished' : 'connecting'); return }
    if (typeof WebSocket === 'undefined') { setConnection('unavailable'); return }
    const key = ['simulation-job', environmentID, jobID]
    let active = true
    let socket: WebSocket | undefined
    let retry: number | undefined
    let attempts = 0
    const connect = () => {
      if (!active) return
      setConnection(attempts ? 'reconnecting' : 'connecting')
      const scheme = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${scheme}//${window.location.host}${base}/simulation-jobs/${encodeURIComponent(jobID)}/stream`)
      socket.onopen = () => { if (active) { attempts = 0; setConnection('connected') } }
      socket.onmessage = message => {
        if (!active) return
        let data: StreamMessage
        try { data = JSON.parse(String(message.data)) as StreamMessage } catch { return }
        if (data.type === 'state' && data.job?.id === jobID) {
          client.setQueryData<Job>(key, previous => {
            if (previous && data.job.event_cursor < previous.event_cursor) return previous
            if (previous?.updated_at && data.job.updated_at && data.job.updated_at < previous.updated_at) return previous
            return data.job
          })
          void client.invalidateQueries({ queryKey: ['simulation-jobs', environmentID] })
        } else if (data.type === 'event' && data.job_id === jobID) {
          client.setQueryData<Job>(key, previous => {
            if (!previous || data.event_cursor <= previous.event_cursor) return previous
            if (data.event_cursor !== previous.event_cursor + 1) { void client.invalidateQueries({ queryKey: key }); return previous }
            return { ...previous, event_cursor: data.event_cursor, updated_at: data.updated_at, events: [...(previous.events || []), data.event] }
          })
        }
      }
      socket.onerror = () => socket?.close()
      socket.onclose = () => {
        if (!active) return
        const current = client.getQueryData<Job>(key)
        if (current?.status === 'completed' || current?.status === 'stopped') { setConnection('finished'); return }
        setConnection('reconnecting')
        void client.invalidateQueries({ queryKey: key })
        attempts += 1
        retry = window.setTimeout(connect, Math.min(8000, 500 * 2 ** Math.min(attempts, 4)))
      }
    }
    connect()
    return () => { active = false; if (retry !== undefined) window.clearTimeout(retry); socket?.close() }
  }, [environmentID, jobID, terminal, client])
  const current = job.data?.events?.at(-1)
  useEffect(() => { if (current) onEventChange(current) }, [current?.id, onEventChange])

  const start = useMutation({ mutationFn: () => request<Job>(`${base}/simulations/${runID}/jobs`, { method: 'POST' }), onSuccess: async item => { setSelectedJobID(item.id); client.setQueryData(['simulation-job', environmentID, item.id], item); await client.invalidateQueries({ queryKey: ['simulation-jobs', environmentID] }) } })
  const control = useMutation({ mutationFn: async ({ action, speed }: { action: 'pause' | 'resume' | 'stop' | 'speed'; speed?: number }) => request<Job>(`${base}/simulation-jobs/${jobID}/${action}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: action === 'speed' ? JSON.stringify({ speed }) : undefined }), onMutate: async () => { await client.cancelQueries({ queryKey: ['simulation-job', environmentID, jobID] }) }, onSuccess: item => { client.setQueryData(['simulation-job', environmentID, jobID], item); void client.invalidateQueries({ queryKey: ['simulation-jobs', environmentID] }) } })
  const active = related.some(item => ['running', 'paused'].includes(item.id === jobID ? job.data?.status || item.status : item.status))

  return <div className="simulation-job-panel">
    <div className="results-top"><strong>Backend event delivery</strong><span>Progress is stored in PostgreSQL. {jobID ? connection === 'connected' ? 'Live stream connected.' : connection === 'finished' ? 'Delivery finished.' : connection === 'unavailable' ? 'Live stream unavailable; refreshing from API.' : 'Reconnecting; refreshing from API.' : 'Select or start a job.'}</span></div>
    {jobs.isPending ? <p className="empty-note">Loading jobs…</p> : jobs.isError ? <p role="alert">Could not load jobs. <button onClick={() => void jobs.refetch()}>Retry</button></p> : null}
    {jobID && job.isPending && <p className="empty-note">Loading job progress…</p>}
    <div className="playback-controls">
      {related.length > 0 && <label>Job<select aria-label="Simulation job" value={jobID} onChange={event => setSelectedJobID(event.target.value)}>{related.map(item => <option value={item.id} key={item.id}>#{item.id.slice(-8)} · {item.status}</option>)}</select></label>}
      {canEdit && <button onClick={() => start.mutate()} disabled={active || start.isPending}>{start.isPending ? 'Starting…' : related.length ? 'Start new delivery' : 'Start delivery'}</button>}
      {job.data && <><span role="status">{job.data.status} · {job.data.event_cursor} / {job.data.total_events} events</span>
        {canEdit && <>
          <button disabled={job.data.status !== 'running' || control.isPending} onClick={() => control.mutate({ action: 'pause' })}>Pause job</button>
          <button disabled={job.data.status !== 'paused' || control.isPending} onClick={() => control.mutate({ action: 'resume' })}>Resume job</button>
          <button disabled={!['running', 'paused'].includes(job.data.status) || control.isPending} onClick={() => control.mutate({ action: 'stop' })}>Stop job</button>
          <label>Job speed<select aria-label="Job speed" value={job.data.speed} disabled={!['running', 'paused'].includes(job.data.status) || control.isPending} onChange={event => control.mutate({ action: 'speed', speed: Number(event.target.value) })}><option value="0.5">0.5×</option><option value="1">1×</option><option value="2">2×</option><option value="4">4×</option></select></label>
        </>}
      </>}
    </div>
    {start.isError && <p className="result-error" role="alert">{start.error.message}</p>}
    {control.isError && <p className="result-error" role="alert">{control.error.message}</p>}
    {job.isError && <p className="result-error" role="alert">Could not load job. <button onClick={() => void job.refetch()}>Retry</button></p>}
    {current && <div className="path-step"><span className="step-number">{String(job.data?.event_cursor || 0).padStart(2, '0')}</span><div><strong>Latest delivered: {current.event_type.replaceAll('_', ' ')}</strong><p>{current.source_asset_id} → {current.target_asset_id} at +{current.timestamp_seconds}s</p><small>{current.result} · {current.detected ? 'Detected' : 'Not detected'}</small></div></div>}
  </div>
}
