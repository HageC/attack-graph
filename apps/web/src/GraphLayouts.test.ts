import { expect, test } from 'vitest'
import { arrangeAssets } from './GraphLayouts'

test('auto arrangement is deterministic and leaves source coordinates untouched',()=>{
 const assets=[{id:'b',name:'Database',segment:'Data',x:700,y:300},{id:'a',name:'App',segment:'Applications',x:200,y:100},{id:'c',name:'Workstation',segment:'Corporate',x:50,y:200}]
 const edges=[{source:'c',target:'a',kind:'CAN_REACH'},{source:'a',target:'b',kind:'HAS_ACCESS_TO'},{source:'b',target:'c',kind:'TRANSITION'}]
 const first=arrangeAssets(assets,edges)
 expect(first).toEqual(arrangeAssets([...assets].reverse(),edges))
 expect(new Set(Object.values(first).map(position=>`${position.x},${position.y}`)).size).toBe(3)
 expect(assets[0].x).toBe(700)
 expect(assets.map(asset=>asset.id)).toEqual(['b','a','c'])
})
