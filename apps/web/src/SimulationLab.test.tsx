// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SimulationLab, { type SimulationEvent } from './SimulationLab'

afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.useRealTimers() })

const events: SimulationEvent[] = [
  { id: 'e1', timestamp_seconds: 0, source_asset_id: 'a', target_asset_id: 'a', event_type: 'simulation_started', transition_id: null, result: 'started', detected: false, severity: 2 },
  { id: 'e2', timestamp_seconds: 5, source_asset_id: 'a', target_asset_id: 'b', event_type: 'transition_attempt', transition_id: 'ab', result: 'succeeded', detected: true, severity: 4 },
  { id: 'e3', timestamp_seconds: 5, source_asset_id: 'b', target_asset_id: 'b', event_type: 'target_reached', transition_id: null, result: 'reached', detected: true, severity: 4 },
]

test('replays a saved run, pauses, steps, and restarts', async () => {
  const saved = { id: 'sim-12345678', seed: 42, summary: { result: 'target_reached', successful_transitions: 1, detected_attempts: 1 }, events }
  vi.stubGlobal('fetch', vi.fn(async (url: string) => ({ ok: true, json: async () => url.endsWith('/simulation-jobs') ? [] : url.endsWith('/simulations') ? [saved] : saved })))
  const onEventChange = vi.fn()
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SimulationLab environmentID="northstar" snapshots={[]} canEdit={false} onEventChange={onEventChange} /></QueryClientProvider>)
  fireEvent.click(await screen.findByRole('button', { name: /12345678/ }))
  expect(await screen.findByText('Event 1 of 3')).toBeTruthy()
  expect(onEventChange).toHaveBeenCalledWith(events[0])
  fireEvent.click(screen.getByRole('button', { name: 'Play' }))
  expect(screen.getByRole('button', { name: 'Pause' })).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Pause' }))
  fireEvent.click(screen.getByRole('button', { name: 'Next event' }))
  await waitFor(() => expect(screen.getByText('Event 2 of 3')).toBeTruthy())
  expect(onEventChange).toHaveBeenCalledWith(events[1])
  fireEvent.click(screen.getByRole('button', { name: 'Restart' }))
  expect(screen.getByText('Event 1 of 3')).toBeTruthy()
  expect(screen.getByRole('button', { name: 'Previous event' }).hasAttribute('disabled')).toBe(true)
})

test('playback advances on a bounded timer and stops at the final event', async () => {
  const saved = { id: 'sim-playback', seed: 7, summary: { result: 'target_reached', successful_transitions: 1, detected_attempts: 1 }, events }
  vi.stubGlobal('fetch', vi.fn(async (url: string) => ({ ok: true, json: async () => url.endsWith('/simulation-jobs') ? [] : url.endsWith('/simulations') ? [saved] : saved })))
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><SimulationLab environmentID="northstar" snapshots={[]} canEdit={false} onEventChange={vi.fn()} /></QueryClientProvider>)
  fireEvent.click(await screen.findByRole('button', { name: /playback/ }))
  expect(await screen.findByText('Event 1 of 3')).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Play' }))
  await waitFor(() => expect(screen.getByText('Event 3 of 3')).toBeTruthy(), { timeout: 2500 })
  await waitFor(() => expect(screen.getByRole('button', { name: 'Play' })).toBeTruthy())
  expect(screen.getByRole('button', { name: 'Next event' }).hasAttribute('disabled')).toBe(true)
})
