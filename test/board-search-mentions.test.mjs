import {test} from 'node:test';
import assert from 'node:assert/strict';
import {boardStateFixture} from './fixtures/board-state.mjs';
import {createBoardSearch} from '../dist/src/board/search.mjs';

// Two tenants whose users, sessions and names collide on purpose.
const alice={tenantId:'team-a',userId:'alice'},bob={tenantId:'team-a',userId:'bob'},carol={tenantId:'team-a',userId:'carol'};
const otherAlice={tenantId:'team-b',userId:'alice'},otherBob={tenantId:'team-b',userId:'bob'};

async function fixture(t){
  const f=await boardStateFixture(t);let time=1700000000000;
  const board=f.make({now:()=>++time}),search=createBoardSearch({state:f.state,now:()=>time});
  const register=async(who,session,name)=>(await board.participate(who,'register',{session,name,task:'mentions fixture',harness:'codex'})).agent;
  const publish=async(who,session,id,text,topic='work')=>(await board.participate(who,'publish',{session,id,topic,text})).accepted[0];
  return {board,search,register,publish};
}
const ids=result=>result.messages.map(m=>m.id);

test('mentionsMe and mentions find posts that mention an identity without consuming deliveries',async t=>{
  const f=await fixture(t);
  const aliceMain=await f.register(alice,'a1','alice-main'),aliceHelper=await f.register(alice,'a2','alice-helper'),bobMain=await f.register(bob,'b1','bob-main');
  const review=await f.publish(bob,'b1','p1','@alice-main please review','review');
  const tests=await f.publish(bob,'b1','p2','@alice-helper run the tests');
  const plain=await f.publish(bob,'b1','p3','nobody is mentioned here');
  const done=await f.publish(alice,'a1','p4','@bob-main done');
  const both=await f.publish(bob,'b1','p5','@alice-main and @bob-main sync up');
  // The same names and sessions in another tenant must never leak across.
  await f.register(otherAlice,'a1','alice-main');await f.register(otherBob,'b1','bob-main');
  const foreign=await f.publish(otherBob,'b1','p1','@alice-main foreign tenant');

  const mine=await f.search.search(alice,{mentionsMe:true,sort:'newest'});
  assert.deepEqual(ids(mine),[both,tests,review]);assert.equal(mine.total,3);
  assert.deepEqual(mine.facets.topic.values,[{value:'work',count:2},{value:'review',count:1}],'facets count only matching posts');
  assert.deepEqual(ids(await f.search.search(bob,{mentionsMe:true,sort:'newest'})),[both,done]);
  assert.deepEqual(ids(await f.search.search(otherAlice,{mentionsMe:true,sort:'newest'})),[foreign]);

  // Explicit identities, alone and together with the other filters.
  assert.deepEqual(ids(await f.search.search(alice,{mentions:[aliceHelper],sort:'newest'})),[tests]);
  assert.deepEqual(ids(await f.search.search(bob,{mentions:[aliceMain,aliceHelper],sort:'newest'})),[both,tests,review]);
  assert.deepEqual(ids(await f.search.search(alice,{mentionsMe:true,mentions:[bobMain],sort:'newest'})),[both],'both filters must match');
  assert.deepEqual(ids(await f.search.search(alice,{mentionsMe:true,topics:['review']})),[review]);
  assert.deepEqual(ids(await f.search.search(alice,{mentionsMe:true,query:'tests'})),[tests]);
  assert.ok(!ids(await f.search.search(alice,{mentionsMe:true})).includes(plain));

  // A caller with no registered identity gets an empty result, not an error.
  const none=await f.search.search(carol,{mentionsMe:true});assert.equal(none.total,0);assert.deepEqual(none.messages,[]);
  // Identities hash the user id and session, so colliding local ids give team-b's alice the same identity. Results
  // still come only from the caller's tenant: team-b sees its own post, never team-a's.
  assert.deepEqual(ids(await f.search.search(otherBob,{mentions:[aliceMain]})),[foreign]);

  // Searching is read-only: alice's listener still receives its pending mentions afterwards.
  const inbox=await f.board.participate(alice,'inbox',{session:'a1'});
  assert.ok(inbox.batch.messages.some(m=>m.id===review));
});

test('mention filters page consistently and cursors stay bound to them',async t=>{
  const f=await fixture(t);
  await f.register(alice,'a1','alice-main');await f.register(bob,'b1','bob-main');
  const posted=[];for(let i=0;i<5;i++)posted.push(await f.publish(bob,'b1','m'+i,`@alice-main item ${i}`));
  await f.publish(bob,'b1','x','unrelated');
  const args={mentionsMe:true,sort:'newest',limit:2};
  const first=await f.search.search(alice,args);assert.equal(first.total,5);
  // A new identity registered mid-paging does not change the remaining pages.
  await f.register(alice,'a2','alice-late');
  let cursor=first.next,all=ids(first);
  while(cursor){const page=await f.search.search(alice,{...args,cursor});assert.equal(page.total,5);all.push(...ids(page));cursor=page.next;}
  assert.deepEqual(all,[...posted].reverse());
  for(const changed of [{...args,mentionsMe:false},{...args,mentions:['a'.repeat(64)]}])
    await assert.rejects(f.search.search(alice,{...changed,cursor:first.next}),{status:409});
  await assert.rejects(f.search.search(bob,{...args,cursor:first.next}),{status:409});
});

test('mention filter input is validated',async t=>{
  const f=await fixture(t);
  for(const input of [{mentions:['alice-main']},{mentions:Array.from({length:9},(_,i)=>String(i).repeat(64).slice(0,64))},{mentionsMe:'yes'}])
    await assert.rejects(f.search.search(alice,input));
});
