import { useState, type FormEvent } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { GitBranch, LockKeyhole, Shield } from 'lucide-react'
import NetworkApp from './App'
import AccountSettings from './AccountSettings'

type User={id:string;email:string}
type Environment={id:string;organization_id:string;name:string;description:string;role:string;asset_count:number}
async function get<T>(url:string):Promise<T>{const response=await fetch(url);if(!response.ok)throw new Error(`Request failed (${response.status})`);return response.json()}

export default function AuthenticatedApp(){
 const queryClient=useQueryClient()
 const me=useQuery({queryKey:['auth-me'],queryFn:()=>get<User>('/api/v1/auth/me'),retry:false})
 const environments=useQuery({queryKey:['environments'],queryFn:()=>get<Environment[]>('/api/v1/environments'),enabled:!!me.data,retry:false})
 const [environmentID,setEnvironmentID]=useState('');const [passwordOpen,setPasswordOpen]=useState(false)
 const [email,setEmail]=useState('');const [password,setPassword]=useState('');const [error,setError]=useState('');const [pending,setPending]=useState(false)
 async function signIn(event:FormEvent){event.preventDefault();setError('');setPending(true);try{const response=await fetch('/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password})});if(!response.ok){setError(response.status===401?'Incorrect email or password.':'Could not sign in.');return};setPassword('');await me.refetch();await environments.refetch()}catch{setError('Could not reach the API. Check that Docker Compose is running.')}finally{setPending(false)}}
 async function signOut(){await fetch('/api/v1/auth/logout',{method:'POST'});setEnvironmentID('');queryClient.setQueryData(['auth-me'],null);queryClient.removeQueries({queryKey:['environments']})}
 if(me.isLoading)return <div className="auth-loading">Checking session…</div>
 if(!me.data)return <main className="login-page"><div className="login-card"><div className="login-brand"><span><GitBranch size={25}/></span><div><strong>ATTACKGRAPH</strong><small>SECURITY INTELLIGENCE</small></div></div><div className="login-kicker"><Shield size={15}/> WORKSPACE ACCESS</div><h1>Sign in to your workspace</h1><p>Explore isolated synthetic enterprise models. No real infrastructure is connected.</p><form onSubmit={signIn}><label>Email<input type="email" autoComplete="username" value={email} onChange={event=>setEmail(event.target.value)} required/></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={event=>setPassword(event.target.value)} required/></label>{error?<div role="alert" className="login-error">{error}</div>:null}<button className="primary" disabled={pending}>{pending?'Signing in…':'Sign in'}</button></form><div className="login-hint"><LockKeyhole size={14}/> Ask your administrator for your account credentials.</div></div></main>
 if(environments.isLoading)return <div className="auth-loading">Loading workspaces…</div>
 if(environments.isError)return <div className="auth-loading">Could not load workspaces. <button onClick={()=>environments.refetch()}>Retry</button></div>
 const items=environments.data||[];if(!items.length)return <div className="auth-loading">No environments are assigned to this account. <button onClick={signOut}>Sign out</button></div>
 const current=items.find(item=>item.id===environmentID)||items[0]
 return <><NetworkApp key={current.id} environmentID={current.id} organizationID={current.organization_id} environmentName={current.name} role={current.role} environments={items} onEnvironmentChange={setEnvironmentID} user={me.data} onSignOut={signOut} onChangePassword={()=>setPasswordOpen(true)}/>{passwordOpen?<AccountSettings onClose={()=>setPasswordOpen(false)} onChanged={()=>{setPasswordOpen(false);setEnvironmentID('');queryClient.setQueryData(['auth-me'],null);queryClient.removeQueries({queryKey:['environments']})}}/>:null}</>
}
