import {applicationDatabaseFixture,postgresUrl} from './fixtures/application-database.mjs';
import {createApplicationState} from '../dist/src/state/application.mjs';
import {createPostgresEventIdentities} from '../dist/src/sessions/postgres-identities.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';
import {Client,StreamableHTTPClientTransport} from '@modelcontextprotocol/client';
import {selfhostApplication} from '../dist/src/selfhost/application.mjs';
import {createLocalIdentity} from '../dist/src/identity/better-auth.mjs';
import {createLocalSessionStore} from '../dist/src/sessions/local-store.mjs';

const org='org_local',setup='setup-token';

async function fixture(t){
  const dir=await mkdtemp(join(tmpdir(),'agent-tokens-selfhost-'));
  t.after(()=>rm(dir,{recursive:true,force:true}));
  const store=createLocalSessionStore(dir),prefix='sessions/selfhost/v1';
  const database=await applicationDatabaseFixture(t),state=await createApplicationState({database});
  const eventIdentities=createPostgresEventIdentities({connectionString:postgresUrl,namespace:database.namespace});
  t.after(()=>eventIdentities.close());
  let app,identity;const server=createServer((req,res)=>app(req,res));
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const url='http://localhost:'+server.address().port;
  t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));await identity?.close();});
  identity=await createLocalIdentity({url,secret:randomBytes(32).toString('hex'),database,organizationId:org});await identity.ready();
  const settings={url,authOrigin:url+'/api/auth',clientId:'opencrawl-cli',organizationId:org,setupToken:setup,search:{endpoint:'http://127.0.0.1:1',environment:'selfhost',tenantId:org}};
  app=selfhostApplication({settings,state,eventIdentities,store,prefix,identity,readAsset:async()=>''});
  const form=(path,body,headers={})=>fetch(url+path,{method:'POST',redirect:'manual',headers:{'content-type':'application/x-www-form-urlencoded',...headers},body:new URLSearchParams(body)});
  const cookieOf=response=>response.headers.getSetCookie().map(line=>line.split(';')[0]).join('; ');
  // A real CLI sign-in through the device grant, as `opencrawl login` does it.
  const login=async cookie=>{
    const device=await(await form('/api/cli/device',{client_id:'opencrawl-cli'})).json();
    assert.equal((await form('/device',{user_code:device.user_code,decision:'approve'},{origin:url,cookie})).status,200);
    const token=await form('/api/cli/token',{client_id:'opencrawl-cli',grant_type:'urn:ietf:params:oauth:grant-type:device_code',device_code:device.device_code});
    assert.equal(token.status,200);return (await token.json()).access_token;
  };
  const signupAdmin=async()=>{const r=await form('/auth/signup',{setup,workspace:'Local team',name:'Ada Admin',email:'ada@example.com',password:'correct horse battery'},{origin:url});assert.equal(r.status,303);return cookieOf(r);};
  const join_=async(name,email)=>{
    const [inviter]=(await identity.directory.userManagement.listOrganizationMemberships({organizationId:org})).data;
    const invited=await identity.directory.userManagement.sendInvitation({organizationId:org,email,inviterUserId:inviter.userId,roleSlug:'member'});
    const r=await form('/auth/signup',{invitation:invited.id,name,password:'another long password'},{origin:url});assert.equal(r.status,303);
    return cookieOf(r);
  };
  const request=(path,{method,body,auth,headers={}}={})=>fetch(url+path,{method:method??(body!==undefined?'POST':'GET'),
    headers:{...(auth?{authorization:'Bearer '+auth}:{}),'content-type':'application/json',...headers},...(body!==undefined?{body:JSON.stringify(body)}:{})});
  const create=auth=>request('/api/agent-tokens',{method:'POST',auth});
  const revoke=(auth,id)=>request('/api/agent-tokens/'+id,{method:'DELETE',auth});
  const mcp=async auth=>{const client=new Client({name:'agent-token-test',version:'1'});await client.connect(new StreamableHTTPClientTransport(new URL(url+'/mcp'),{requestInit:{headers:{authorization:'Bearer '+auth}}}));return client;};
  return {url,identity,login,signupAdmin,join:join_,request,create,revoke,mcp};
}

test('self-host agent access tokens act as their member on the board, MCP and upload, and fail closed everywhere else',{skip:!postgresUrl},async t=>{
  const f=await fixture(t);
  const adminCookie=await f.signupAdmin(),human=await f.login(adminCookie);

  // Created only from the member's own CLI sign-in, with the exact shape the CLI validates.
  const created=await f.create(human);
  assert.equal(created.status,200);assert.equal(created.headers.get('cache-control'),'no-store');
  const {schemaVersion,data}=await created.json();
  assert.equal(schemaVersion,1);assert.match(data.id,/^[a-f0-9]{64}$/);assert.match(data.token,/^[A-Za-z0-9_.-]{20,512}$/);
  assert.ok(Date.parse(data.expiresAt)>Date.now());
  const agent=data.token;

  for(const [path,options,status] of [
    ['/api/agent-tokens',{method:'POST'},401],
    ['/api/agent-tokens',{method:'POST',auth:'not-a-token'},401],
    ['/api/agent-tokens',{method:'POST',auth:human,headers:{origin:f.url}},403],
    ['/api/agent-tokens',{method:'GET',auth:human},405],
    ['/api/agent-tokens/'+data.id,{method:'POST',auth:human},405],
    ['/api/agent-tokens/not-an-id',{method:'DELETE',auth:human},404],
    // A token can neither create nor revoke tokens, including itself.
    ['/api/agent-tokens',{method:'POST',auth:agent},403],
    ['/api/agent-tokens/'+data.id,{method:'DELETE',auth:agent},403],
  ])assert.equal((await f.request(path,options)).status,status,`${options.method} ${path}`);

  // It acts as the member who created it.
  const me=await f.request('/api/cli/me',{auth:agent});assert.equal(me.status,200);
  const who=(await me.json()).data;assert.equal(who.user.email,'ada@example.com');assert.equal(who.workspace.id,org);
  assert.equal((await f.request('/api/board/register',{body:{session:'machine-1',name:'cloud-agent',task:'Agent token fixture',harness:'other'},auth:agent})).status,200);
  assert.equal((await f.request('/api/board/publish',{body:{session:'machine-1',id:'p1',topic:'deploy',text:'posted with an agent token'},auth:agent})).status,200);
  const client=await f.mcp(agent);
  try{
    assert.equal((await client.callTool({name:'test_connection',arguments:{}})).structuredContent.connected,true);
    const found=await client.callTool({name:'board_search',arguments:{query:'',sort:'newest'}});
    assert.notEqual(found.isError,true);assert.match(JSON.stringify(found),/posted with an agent token/);
  }finally{await client.close();}

  // Upload works; it is write-only there, like a capture credential, so it cannot mint a longer-lived one.
  const owner=(await (await f.request('/api/sessions/identity',{auth:agent})).json()).data.principal;
  assert.equal(owner.captureAccess,'write');assert.equal(owner.tenantId,org);
  const batch={schemaVersion:1,installationId:'fixture',sessionId:'machine-1',harness:'claude-code',origin:'cloud',captureMode:'live',owner,
    events:[{id:'event',kind:'message',data:{role:'user',content:'agent token upload'},sequence:0}],attachments:[]};
  const uploaded=await f.request('/api/sessions/batches',{body:batch,auth:agent});assert.equal(uploaded.status,200,await uploaded.clone().text());
  assert.equal((await f.request('/api/sessions/credentials',{body:{},auth:agent})).status,403);
  // No console, team or library management.
  assert.equal((await f.request('/api/console/bootstrap',{auth:agent})).status,401);

  // A capture credential is not an agent token, even though both are occ1_ tokens.
  const capture=(await (await f.request('/api/sessions/credentials',{body:{},auth:human})).json()).data.token;
  assert.match(capture,/^occ1_/);
  assert.equal((await f.request('/api/cli/me',{auth:capture})).status,401);
  assert.equal((await f.request('/api/board/register',{body:{session:'machine-2',name:'capture-only',task:'x',harness:'other'},auth:capture})).status,401);
  await assert.rejects(f.mcp(capture));

  // Another member cannot revoke this member's token; its owner can, and it stops working at once.
  const bobCookie=await f.join('Bob','bob@example.com'),bob=await f.login(bobCookie);
  assert.equal((await f.revoke(bob,data.id)).status,403);
  assert.equal((await f.request('/api/cli/me',{auth:agent})).status,200);
  const revoked=await f.revoke(human,data.id);assert.equal(revoked.status,200);
  assert.deepEqual((await revoked.json()).data,{id:data.id,revoked:true});
  assert.equal((await f.revoke(human,data.id)).status,200,'revoking again is harmless');
  assert.equal((await f.request('/api/cli/me',{auth:agent})).status,401);
  assert.equal((await f.request('/api/board/inbox',{body:{session:'machine-1'},auth:agent})).status,401);
  assert.equal((await f.request('/api/sessions/batches',{body:batch,auth:agent})).status,401);
  await assert.rejects(f.mcp(agent));

  // Membership is checked on every request: a member who loses it loses their tokens, even before any revocation.
  const bobAgent=(await (await f.create(bob)).json()).data.token;
  assert.equal((await f.request('/api/cli/me',{auth:bobAgent})).status,200);
  const [membership]=(await f.identity.directory.userManagement.listOrganizationMemberships({organizationId:org})).data.filter(m=>m.userId!==who.user.id);
  await f.identity.directory.userManagement.deleteOrganizationMembership(membership.id);
  assert.equal((await f.request('/api/cli/me',{auth:bobAgent})).status,403);
  assert.notEqual((await f.request('/api/board/register',{body:{session:'bob-1',name:'bob-agent',task:'x',harness:'other'},auth:bobAgent})).status,200);
  assert.equal((await f.request('/api/sessions/identity',{auth:bobAgent})).status,403);
  await assert.rejects(f.mcp(bobAgent));
});

test('removing a member through the console revokes their agent access tokens',{skip:!postgresUrl},async t=>{
  const f=await fixture(t);
  const adminCookie=await f.signupAdmin();
  const carolCookie=await f.join('Carol','carol@example.com'),carol=await f.login(carolCookie);
  const token=(await (await f.create(carol)).json()).data.token;
  assert.equal((await f.request('/api/cli/me',{auth:token})).status,200);
  const carolId=(await (await f.request('/api/cli/me',{auth:token})).json()).data.user.id;
  const removed=await f.request('/api/console/team/remove',{body:{userId:carolId},headers:{origin:f.url,cookie:adminCookie}});
  assert.equal(removed.status,200);
  assert.equal((await f.request('/api/cli/me',{auth:token})).status,401,'revoked, not only refused for membership');
});
