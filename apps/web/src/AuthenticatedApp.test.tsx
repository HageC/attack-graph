// @vitest-environment jsdom
import { afterEach, expect, test, vi } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AuthenticatedApp from './AuthenticatedApp'

vi.mock('./App',()=>({default:({environmentName}:{environmentName:string})=><div>Workspace: {environmentName}</div>}))
afterEach(()=>{cleanup();vi.unstubAllGlobals()})

test('signs in and loads only the assigned environment',async()=>{
 let signedIn=false
 vi.stubGlobal('fetch',vi.fn(async(input:string,options?:RequestInit)=>{
  if(input==='/api/v1/auth/me')return signedIn?{ok:true,json:async()=>({id:'user-northstar',email:'analyst@northstar.local'})}:{ok:false,status:401}
  if(input==='/api/v1/auth/login'&&options?.method==='POST'){signedIn=true;return {ok:true,json:async()=>({id:'user-northstar',email:'analyst@northstar.local'})}}
  if(input==='/api/v1/environments')return {ok:true,json:async()=>[{id:'northstar',name:'Northstar Financial',description:'Demo',role:'admin',asset_count:10}]}
  throw new Error(`Unexpected request ${input}`)
 }))
 render(<QueryClientProvider client={new QueryClient({defaultOptions:{queries:{retry:false}}})}><AuthenticatedApp/></QueryClientProvider>)
 const user=userEvent.setup()
 await screen.findByRole('heading',{name:'Sign in to your workspace'})
 await user.type(screen.getByLabelText('Email'),'analyst@northstar.local')
 await user.type(screen.getByLabelText('Password'),'local password')
 await user.click(screen.getByRole('button',{name:'Sign in'}))
 expect(await screen.findByText('Workspace: Northstar Financial')).toBeTruthy()
})
