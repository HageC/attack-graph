import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Users } from 'lucide-react'

type User = {id:string;email:string;role:'viewer'|'editor'|'admin'}
type Environment = {id:string;name:string}
type Props = {organizationID:string;onEnvironmentCreated:(id:string)=>void}

async function request<T>(url:string,method='GET',body?:unknown):Promise<T>{
 const response=await fetch(url,{method,headers:body?{'Content-Type':'application/json'}:undefined,body:body?JSON.stringify(body):undefined})
 const data=await response.json()
 if(!response.ok)throw new Error(data.error?.message||'Request failed')
 return data
}

export default function OrganizationSettings({organizationID,onEnvironmentCreated}:Props){
 const client=useQueryClient();const [open,setOpen]=useState(false);const [email,setEmail]=useState('');const [password,setPassword]=useState('');const [role,setRole]=useState<User['role']>('viewer');const [name,setName]=useState('');const [description,setDescription]=useState('');const [notice,setNotice]=useState('')
 const users=useQuery({queryKey:['organization-users',organizationID],queryFn:()=>request<User[]>(`/api/v1/organizations/${organizationID}/users`),enabled:open})
 const addUser=useMutation({mutationFn:()=>request<User>(`/api/v1/organizations/${organizationID}/users`,'POST',{email,password,role}),onSuccess:()=>{setEmail('');setPassword('');setNotice('Account created. Share its credentials through your approved channel.');void client.invalidateQueries({queryKey:['organization-users',organizationID]})},onError:(error)=>setNotice(error.message)})
 const addEnvironment=useMutation({mutationFn:()=>request<Environment>(`/api/v1/organizations/${organizationID}/environments`,'POST',{name,description}),onSuccess:(env)=>{setName('');setDescription('');setNotice('Environment created.');void client.invalidateQueries({queryKey:['environments']});onEnvironmentCreated(env.id)},onError:(error)=>setNotice(error.message)})
 function submitUser(event:FormEvent){event.preventDefault();setNotice('');addUser.mutate()}
 function submitEnvironment(event:FormEvent){event.preventDefault();setNotice('');addEnvironment.mutate()}
 return <section className="org-settings" aria-label="Organization administration"><div className="workbench-head"><div><div className="eyebrow">ADMINISTRATION</div><h2>Organization access</h2><p>Create accounts and isolated synthetic environments for this organization.</p></div><button className="secondary" onClick={()=>setOpen(!open)} aria-expanded={open}><Users size={15}/>{open?'Hide settings':'Manage organization'}</button></div>{open?<><p className="org-id">Organization ID: {organizationID}</p>{notice?<p role="status" className="edit-notice">{notice}</p>:null}<div className="org-grid"><div className="workbench-box"><div className="workbench-box-head"><h3>Accounts</h3><span>{users.data?.length||0}</span></div>{users.isLoading?<p className="quiet">Loading accounts…</p>:users.isError?<p className="error-note">Could not load accounts. <button onClick={()=>users.refetch()}>Retry</button></p>:<ul className="org-users">{users.data?.map(user=><li key={user.id}><span>{user.email}</span><b>{user.role}</b></li>)}</ul>}<form onSubmit={submitUser} className="org-form"><h4>Add account</h4><label>Email<input type="email" required value={email} onChange={event=>setEmail(event.target.value)} autoComplete="off"/></label><label>Initial password<input type="password" required minLength={12} maxLength={128} value={password} onChange={event=>setPassword(event.target.value)} autoComplete="new-password"/></label><label>Role<select value={role} onChange={event=>setRole(event.target.value as User['role'])}><option value="viewer">Viewer</option><option value="editor">Editor</option><option value="admin">Administrator</option></select></label><button className="secondary" disabled={addUser.isPending}><Plus size={14}/>{addUser.isPending?'Creating…':'Create account'}</button></form></div><div className="workbench-box"><div className="workbench-box-head"><h3>Environments</h3></div><p>New environments start empty and are visible to all members of this organization.</p><form onSubmit={submitEnvironment} className="org-form"><h4>Add environment</h4><label>Name<input required minLength={2} maxLength={100} value={name} onChange={event=>setName(event.target.value)}/></label><label>Description<textarea maxLength={500} value={description} onChange={event=>setDescription(event.target.value)}/></label><button className="secondary" disabled={addEnvironment.isPending}><Plus size={14}/>{addEnvironment.isPending?'Creating…':'Create environment'}</button></form></div></div></>:null}</section>
}
