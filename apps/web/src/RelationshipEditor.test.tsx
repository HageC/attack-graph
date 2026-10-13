// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import RelationshipEditor from './RelationshipEditor'

afterEach(()=>{cleanup();vi.unstubAllGlobals()})
test('requires topology and weakness, then posts a constrained transition',async()=>{
 const assets=[{id:'a',name:'Application',type:'application',segment:'DMZ',ip:'10.0.0.1',criticality:3,risk:50,x:0,y:0},{id:'b',name:'Database',type:'database',segment:'Data',ip:'10.0.0.2',criticality:5,risk:70,x:0,y:0}]
 const edges=[{id:'rel-1',source:'a',target:'b',kind:'CAN_REACH'}]
 const vulnerability={id:'AG-1',asset_id:'a',title:'Modeled weakness',description:'',severity:'high',cvss:8,mitigation:'',state:'active' as const}
 let posted:Record<string,unknown>|undefined
 vi.stubGlobal('fetch',vi.fn(async(_url:string,options?:RequestInit)=>{posted=JSON.parse(String(options?.body));return {ok:true,json:async()=>({id:'tr-1'})}}))
 const user=userEvent.setup()
 const view=render(<QueryClientProvider client={new QueryClient()}><RelationshipEditor environmentID="northstar" assets={assets} edges={[]} selected="a" vulnerabilities={[]}/></QueryClientProvider>)
 expect(screen.getByRole('button',{name:'Save transition'}).hasAttribute('disabled')).toBe(true)
 view.rerender(<QueryClientProvider client={new QueryClient()}><RelationshipEditor environmentID="northstar" assets={assets} edges={edges} selected="a" vulnerabilities={[{...vulnerability,state:'mitigated'}]}/></QueryClientProvider>)
 expect(screen.getByRole('button',{name:'Save transition'}).hasAttribute('disabled')).toBe(true)
 view.rerender(<QueryClientProvider client={new QueryClient()}><RelationshipEditor environmentID="northstar" assets={assets} edges={edges} selected="a" vulnerabilities={[vulnerability]}/></QueryClientProvider>)
 await user.type(screen.getByLabelText('Why is the step feasible?'),'Modeled access permits movement')
 await user.click(screen.getByRole('button',{name:'Save transition'}))
 await waitFor(()=>expect(posted).toBeDefined())
 expect(posted).toMatchObject({source:'a',target:'b',required_relationship:'CAN_REACH',vulnerability_id:'AG-1',required_capability:'foothold'})
})
