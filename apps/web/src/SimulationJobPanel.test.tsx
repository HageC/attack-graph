// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest'
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SimulationJobPanel from './SimulationJobPanel'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

test('starts a backend job and sends pause, resume, speed, and stop actions', async () => {
  let job = { id: 'job-12345678', run_id: 'sim-one', status: 'running', event_cursor: 1, total_events: 3, speed: 1, events: [{ id: 'event-one', event_type: 'simulation_started', source_asset_id: 'a', target_asset_id: 'a', timestamp_seconds: 0, result: 'started', detected: false }] }
  let jobs: typeof job[] = []
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
    calls.push(`${options?.method || 'GET'} ${url}`)
    if (url.endsWith('/jobs') && options?.method === 'POST') jobs = [job]
    if (url.endsWith('/pause')) job = { ...job, status: 'paused' }
    if (url.endsWith('/resume')) job = { ...job, status: 'running' }
    if (url.endsWith('/stop')) job = { ...job, status: 'stopped' }
    if (url.endsWith('/speed')) job = { ...job, speed: JSON.parse(String(options?.body)).speed }
    return { ok: true, json: async () => url.endsWith('/simulation-jobs') ? jobs : job }
  }))
  const onEventChange = vi.fn()
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SimulationJobPanel environmentID="northstar" runID="sim-one" canEdit onEventChange={onEventChange} /></QueryClientProvider>)
  fireEvent.click(await screen.findByRole('button', { name: 'Start delivery' }))
  expect(await screen.findByRole('status')).toHaveProperty('textContent', 'running · 1 / 3 events')
  await waitFor(() => expect(onEventChange).toHaveBeenCalledWith(job.events[0]))
  fireEvent.click(screen.getByRole('button', { name: 'Pause job' }))
  await waitFor(() => expect(screen.getByRole('status').textContent).toContain('paused'))
  fireEvent.change(screen.getByLabelText('Job speed'), { target: { value: '2' } })
  await waitFor(() => expect(calls.some(call => call.endsWith('/speed'))).toBe(true))
  fireEvent.click(screen.getByRole('button', { name: 'Resume job' }))
  await waitFor(() => expect(screen.getByRole('status').textContent).toContain('running'))
  fireEvent.click(screen.getByRole('button', { name: 'Stop job' }))
  await waitFor(() => expect(screen.getByRole('status').textContent).toContain('stopped'))
  expect(screen.getByRole('button', { name: 'Resume job' }).hasAttribute('disabled')).toBe(true)
})

test('WebSocket events advance the job and a disconnect triggers API recovery', async () => {
  const event = { id: 'event-one', event_type: 'simulation_started', source_asset_id: 'a', target_asset_id: 'a', timestamp_seconds: 0, result: 'started', detected: false, severity: 2 }
  const initial = { id: 'job-live', run_id: 'sim-one', status: 'running', event_cursor: 0, total_events: 2, speed: 1, events: [], updated_at: '2026-01-01T00:00:00Z' }
  const fetchCalls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string) => { fetchCalls.push(url); return { ok: true, json: async () => url.endsWith('/simulation-jobs') ? [initial] : initial } }))
  class Socket {
    static instances: Socket[] = []
    url: string
    onopen: (() => void) | null = null
    onmessage: ((message: { data: string }) => void) | null = null
    onclose: (() => void) | null = null
    onerror: (() => void) | null = null
    constructor(url: string) { this.url = url; Socket.instances.push(this) }
    close() { this.onclose?.() }
  }
  vi.stubGlobal('WebSocket', Socket)
  const onEventChange = vi.fn()
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SimulationJobPanel environmentID="northstar" runID="sim-one" canEdit onEventChange={onEventChange} /></QueryClientProvider>)
  await waitFor(() => expect(Socket.instances.length).toBe(1))
  expect(Socket.instances[0].url).toContain('/simulation-jobs/job-live/stream')
  act(() => Socket.instances[0].onopen?.())
  expect(screen.getByText('Live stream connected.', { exact: false })).toBeTruthy()
  act(() => Socket.instances[0].onmessage?.({ data: JSON.stringify({ type: 'event', job_id: 'job-live', event_cursor: 1, event, updated_at: '2026-01-01T00:00:01Z' }) }))
  await waitFor(() => expect(screen.getByRole('status').textContent).toContain('1 / 2 events'))
  expect(onEventChange).toHaveBeenCalledWith(event)
  act(() => Socket.instances[0].close())
  await waitFor(() => expect(screen.getByText('Reconnecting; refreshing from API.', { exact: false })).toBeTruthy())
  await waitFor(() => expect(fetchCalls.filter(url => url.endsWith('/simulation-jobs/job-live')).length).toBeGreaterThan(1))
})
