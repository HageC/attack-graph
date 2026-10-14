import { useState, type FormEvent } from 'react'
import { LayoutGrid, Plus, Trash2 } from 'lucide-react'

export type LayoutPosition={x:number;y:number}
export type SavedLayout={id:string;name:string;positions:Record<string,LayoutPosition>;updated_at:string}
type Asset={id:string;name:string;segment:string;x:number;y:number}
type Edge={source:string;target:string;kind:string}
type Props={layouts:SavedLayout[];activeID:string;canEdit:boolean;pending:boolean;error:string;onSelect:(id:string)=>void;onCreate:(name:string,arranged:boolean)=>void;onDelete:()=>void}

export function arrangeAssets(assets:Asset[],edges:Edge[]):Record<string,LayoutPosition>{
 const byID=new Map(assets.map(asset=>[asset.id,asset]));const outgoing=new Map<string,string[]>();const incoming=new Map(assets.map(asset=>[asset.id,0]))
 for(const edge of edges){if(edge.kind==='TRANSITION'||!byID.has(edge.source)||!byID.has(edge.target))continue;outgoing.set(edge.source,[...(outgoing.get(edge.source)||[]),edge.target]);incoming.set(edge.target,(incoming.get(edge.target)||0)+1)}
 const depth=new Map<string,number>();const queue:string[]=[]
 const roots=assets.filter(asset=>incoming.get(asset.id)===0).sort((a,b)=>a.id.localeCompare(b.id))
 for(const asset of roots){depth.set(asset.id,0);queue.push(asset.id)}
 for(const asset of [...roots,...[...assets].sort((a,b)=>a.id.localeCompare(b.id))]){
  if(!depth.has(asset.id)){depth.set(asset.id,0);queue.push(asset.id)}
  while(queue.length){const source=queue.shift()!;for(const target of outgoing.get(source)||[]){if(depth.has(target))continue;depth.set(target,(depth.get(source)||0)+1);queue.push(target)}}
 }
 const ordered=[...assets].sort((a,b)=>(depth.get(a.id)||0)-(depth.get(b.id)||0)||a.segment.localeCompare(b.segment)||a.name.localeCompare(b.name)||a.id.localeCompare(b.id))
 const columns=Math.min(8,Math.max(1,Math.ceil(Math.sqrt(ordered.length))))
 return Object.fromEntries(ordered.map((asset,index)=>[asset.id,{x:80+(index%columns)*270,y:80+Math.floor(index/columns)*120}]))
}

export default function GraphLayouts({layouts,activeID,canEdit,pending,error,onSelect,onCreate,onDelete}:Props){
 const [name,setName]=useState('')
 function submit(event:FormEvent){event.preventDefault();const trimmed=name.trim();if(trimmed.length<2)return;onCreate(trimmed,false);setName('')}
 const nextAutoName=(()=>{let n=1;while(layouts.some(layout=>layout.name.toLowerCase()===`auto layout ${n}`))n++;return `Auto layout ${n}`})()
 return <div className="layout-controls"><label>GRAPH LAYOUT<select aria-label="Graph layout" value={activeID} onChange={event=>onSelect(event.target.value)}><option value="default">Default layout</option>{layouts.map(layout=><option key={layout.id} value={layout.id}>{layout.name}</option>)}</select></label>{canEdit?<><form onSubmit={submit}><label className="sr-only" htmlFor="layout-name">New layout name</label><input id="layout-name" maxLength={80} minLength={2} value={name} onChange={event=>setName(event.target.value)} placeholder="New layout name"/><button className="secondary" disabled={pending||name.trim().length<2} title="Save current positions"><Plus size={14}/> Save current</button></form><button className="secondary" disabled={pending} onClick={()=>onCreate(name.trim()||nextAutoName,true)}><LayoutGrid size={14}/> Auto arrange</button>{activeID!=='default'?<button className="layout-delete" disabled={pending} onClick={()=>{if(window.confirm("Delete this saved layout?"))onDelete()}} aria-label="Delete selected layout"><Trash2 size={15}/></button>:null}</>:null}{error?<span role="alert" className="layout-error">{error}</span>:null}</div>
}
