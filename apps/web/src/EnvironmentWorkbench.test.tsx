// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest'
import { cleanup, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import EnvironmentWorkbench, { type Asset } from './EnvironmentWorkbench'

const asset:Asset={id:'app-01',name:'Payments API',type:'application',segment:'Applications',ip:'10.20.30.12',criticality:4,risk:96,x:100,y:100}
afterEach(()=>{cleanup();vi.unstubAllGlobals()})
function renderWorkbench(canEdit=true){return render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><EnvironmentWorkbench environmentID="northstar" canEdit={canEdit} assets={[asset]} edges={[]} selected="app-01" onSelect={()=>{}}/></QueryClientProvider>)}

test('filters server vulnerabilities and submits a synthetic asset',async()=>{
 const calls:{url:string;method:string;body?:Record<string,unknown>}[]=[]
 vi.stubGlobal('fetch',vi.fn(async(input:string,options?:RequestInit)=>{
  const method=options?.method||'GET';const body=options?.body?JSON.parse(String(options.body)):undefined;calls.push({url:input,method,body})
  if(input.endsWith('/vulnerabilities'))return {ok:true,json:async()=>[{id:'AG-003',asset_id:'app-01',title:'Broad ledger access',description:'Synthetic',severity:'critical',cvss:9.1,mitigation:'Reduce grants'}]}
  if(input.endsWith('/assets')&&method==='POST')return {ok:true,json:async()=>({...body,id:'asset-new',risk:16,x:120,y:120})}
  throw new Error('Unexpected request')
 }))
 const user=userEvent.setup();renderWorkbench()
 await screen.findByRole('button',{name:/Broad ledger access/})
 await user.type(screen.getByPlaceholderText('Title, severity, asset'),'no match')
 expect(screen.queryByRole('button',{name:/Broad ledger access/})).toBeNull()
 await user.clear(screen.getByPlaceholderText('Title, severity, asset'))
 await user.type(screen.getByPlaceholderText('Title, severity, asset'),'ledger')
 expect(screen.getByRole('button',{name:/Broad ledger access/})).toBeTruthy()
 await user.click(screen.getByRole('button',{name:'Add asset'}))
 const form=screen.getByRole('form',{name:'Asset editor'})
 await user.type(within(form).getByLabelText('Name'),'Finance workstation')
 await user.click(within(form).getByRole('button',{name:'Save asset'}))
 await waitFor(()=>expect(calls.some(c=>c.method==='POST'&&c.url.endsWith('/assets')&&c.body?.name==='Finance workstation')).toBe(true))
})

test('viewer sees model data without editing actions',async()=>{
 vi.stubGlobal('fetch',vi.fn(async()=>({ok:true,json:async()=>[]})))
 renderWorkbench(false)
 await screen.findByText('VIEWER ACCESS')
 expect(screen.queryByRole('button',{name:'Add asset'})).toBeNull()
 expect(screen.queryByRole('button',{name:'Save relationship'})).toBeNull()
})
