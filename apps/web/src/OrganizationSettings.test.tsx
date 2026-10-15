// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import OrganizationSettings from './OrganizationSettings'

afterEach(()=>{cleanup();vi.unstubAllGlobals()})
test('admin can add an account and an environment',async()=>{
 const calls:{url:string;body:Record<string,string>}[]=[]
 vi.stubGlobal('fetch',vi.fn(async(url:string,options?:RequestInit)=>{
  if(!options?.method || options.method==='GET')return {ok:true,json:async()=>[{id:'u1',email:'admin@example.invalid',role:'admin'}]}
  const body=JSON.parse(String(options.body));calls.push({url,body})
  if(url.endsWith('/users'))return {ok:true,json:async()=>({id:'u2',email:body.email,role:body.role})}
  return {ok:true,json:async()=>({id:'env-new',name:body.name})}
 }))
 const created=vi.fn();const user=userEvent.setup()
 render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><OrganizationSettings organizationID="org-test" onEnvironmentCreated={created}/></QueryClientProvider>)
 await user.click(screen.getByRole('button',{name:'Manage organization'}))
 expect(await screen.findByText('admin@example.invalid')).toBeTruthy()
 await user.type(screen.getByLabelText('Email'),'viewer@example.invalid')
 await user.type(screen.getByLabelText('Initial password'),'initial-pass-123')
 await user.click(screen.getByRole('button',{name:'Create account'}))
 await waitFor(()=>expect(calls.some(call=>call.url.endsWith('/users')&&call.body.role==='viewer')).toBe(true))
 await user.type(screen.getByLabelText('Name'),'New test environment')
 await user.click(screen.getByRole('button',{name:'Create environment'}))
 await waitFor(()=>expect(created).toHaveBeenCalledWith('env-new'))
})
