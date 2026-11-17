import type {IncomingMessage,ServerResponse} from 'node:http';
import type {ApplicationState} from '../state/types.mjs';
import type {HostedUser,IdentityDirectory,Principal} from '../identity/types.mjs';
import {currentVerifiedUser} from '../identity/auth.mjs';
import {createCaptureCredentials} from '../sessions/credentials.mjs';
import {errorInfo} from '../errors.mjs';

type Identified={status:200;user:{id:string;email:string};principal:Principal}|{status:401|403|503;code?:string};
type HumanResult={status:number;principal?:Principal;code?:string};

/**
 * Agent access tokens for machines that cannot sign in themselves, such as a cloud
 * platform's fresh machine per task. A token is an opaque delegated credential with
 * purpose "agent" in the existing credential store: only its hash is kept, it expires
 * and its owner can revoke it. It acts as the member who created it on search, the
 * board, MCP and capture upload. Every request rechecks the credential, the account and
 * the active membership; nothing is cached. Creating and revoking tokens requires that
 * member's own CLI sign-in, so a token can never create or extend another credential.
 */
export function selfhostAgentTokens({state,directory,organizationId,resolve,identifyHuman,nonHuman}:{
  state:ApplicationState;directory:IdentityDirectory;organizationId:string;
  resolve:(user:Pick<HostedUser,'id'>)=>Promise<Principal|null>;
  identifyHuman:(authorization:string|undefined)=>Promise<HumanResult>;
  nonHuman:(token:string|undefined)=>boolean;
}){
  const credentials=createCaptureCredentials({state,purpose:'agent'});

  async function identify(token:string):Promise<Identified>{
    let delegated;
    try{delegated=await credentials.authenticate(token);}catch{return {status:503};}
    if(!delegated||delegated.tenantId!==organizationId)return {status:401};
    const current=await currentVerifiedUser(directory,delegated.userId);
    if(current.status!==200)return current;
    const principal=await resolve(current.user).catch(()=>undefined);
    if(principal===undefined)return {status:503};
    if(!principal)return {status:403,code:'ORGANIZATION_REQUIRED'};
    const {user}=current;
    return {status:200,user:{id:user.id,email:user.email},principal:{...principal,email:user.email,name:[user.firstName,user.lastName].filter(Boolean).join(' ')||null}};
  }

  // POST /api/agent-tokens creates one; DELETE /api/agent-tokens/<id> revokes one. The CLI reads 404 and 405 as
  // "this deployment does not offer agent access tokens", so unknown paths and methods keep those meanings.
  async function handle(req:IncomingMessage,res:ServerResponse,path:string){
    const send=(status:number,body:Record<string,unknown>)=>{res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify({schemaVersion:1,...body}));};
    const failure=(status:number,code:string,message:string)=>send(status,{error:{code,message}});
    const revokeId=/^\/api\/agent-tokens\/([a-f0-9]{64})$/.exec(path)?.[1];
    if(path!=='/api/agent-tokens'&&!revokeId)return failure(404,'NOT_FOUND','Not found');
    if(req.method!==(revokeId?'DELETE':'POST'))return failure(405,'METHOD_NOT_ALLOWED','Method not allowed');
    if(req.headers.origin)return failure(403,'BROWSER_REQUEST_DENIED','Browser request denied');
    const token=/^Bearer (.+)$/i.exec(req.headers.authorization||'')?.[1];
    if(nonHuman(token))return failure(403,'HUMAN_SIGN_IN_REQUIRED','Managing agent access tokens needs your own sign-in, not a token.');
    const human=await identifyHuman(req.headers.authorization);
    if(human.status!==200||!human.principal)return human.status===403?failure(403,human.code||'ACCESS_DENIED','Workspace membership required'):failure(human.status===503?503:401,human.status===503?'UNAVAILABLE':'AUTH_REQUIRED','Sign in with opencrawl login');
    if(human.principal.tenantId!==organizationId||human.principal.captureAccess!==undefined)return failure(403,'ACCESS_DENIED','Workspace access denied');
    try{
      if(revokeId){await credentials.revoke(human.principal,revokeId);return send(200,{data:{id:revokeId,revoked:true}});}
      const {id,token:created,expiresAt}=await credentials.issue(human.principal);
      return send(200,{data:{id,token:created,expiresAt}});
    }catch(error){
      const status=errorInfo(error).status;
      return status===403?failure(403,'ACCESS_DENIED','This account cannot manage that agent access token.'):failure(503,'UNAVAILABLE','Agent access tokens are temporarily unavailable.');
    }
  }

  return {identify,handle,revokeAll:(principal:Principal)=>credentials.revokeAll(principal)};
}
