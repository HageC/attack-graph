// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import DetectionLab from './DetectionLab'

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

test('explores delivered telemetry and manages a declarative rule', async () => {
  const telemetry = [{ id: 'tel-1', job_id: 'job-1', run_id: 'sim-1', sequence: 2, schema_version: 1, occurred_at_seconds: 8, event_type: 'endpoint_alert', asset_id: 'id-01', source_asset_id: 'ws-01', result: 'observed', severity: 4, detected: true, ground_truth: 'control', payload: { synthetic: true }, created_at: '2026-01-01T00:00:00Z' }]
  const alerts = [{ id: 'alert-1', rule_id: 'rule-1', rule_name: 'Identity endpoint alert', job_id: 'job-1', telemetry_id: 'tel-1', event_type: 'endpoint_alert', asset_id: 'id-01', severity: 4, created_at: '2026-01-01T00:00:00Z' }]
  let rules: { id: string; name: string; event_type: string; min_severity: number; asset_id: string; enabled: boolean }[] = []
  const calls: string[] = []
  vi.stubGlobal('fetch', vi.fn(async (url: string, options?: RequestInit) => {
    calls.push(`${options?.method || 'GET'} ${url}`)
    if (url.includes('/detection-rules/') && url.endsWith('/test')) return { ok: true, json: async () => ({ rule_id: 'rule-1', match_count: 1, telemetry_ids: ['tel-1'], truncated: false }) }
    if (url.includes('/detection-rules/') && options?.method === 'PATCH') { rules = rules.map(rule => ({ ...rule, enabled: JSON.parse(String(options.body)).enabled })); return { ok: true, json: async () => rules[0] } }
    if (url.endsWith('/detection-rules') && options?.method === 'POST') { rules = [{ id: 'rule-1', enabled: true, ...JSON.parse(String(options.body)) }]; return { ok: true, json: async () => rules[0] } }
    return { ok: true, json: async () => url.includes('/telemetry?') ? telemetry : url.includes('/alerts?') ? alerts : rules }
  }))
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><DetectionLab environmentID="northstar" assets={[{ id: 'id-01', name: 'Identity' }]} canEdit /></QueryClientProvider>)
  expect(await screen.findByText('Event detail')).toBeTruthy()
  expect(screen.getByText('v1')).toBeTruthy()
  expect(screen.getByText('Identity endpoint alert')).toBeTruthy()
  fireEvent.change(screen.getByLabelText('Rule name'), { target: { value: 'Identity endpoint alert' } })
  fireEvent.change(screen.getByLabelText('Rule asset'), { target: { value: 'id-01' } })
  fireEvent.click(screen.getByRole('button', { name: 'Create rule' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Test history' })).toBeTruthy())
  fireEvent.click(screen.getByRole('button', { name: 'Test history' }))
  expect(await screen.findByText(/Historical test: 1 matching events/)).toBeTruthy()
  fireEvent.click(screen.getByRole('button', { name: 'Disable' }))
  await waitFor(() => expect(screen.getByRole('button', { name: 'Enable' })).toBeTruthy())
  expect(calls.some(call => call.includes('/detection-rules/rule-1/test'))).toBe(true)
})
