import os
from typing import Annotated

import typer

from lib.attacks import postex
from lib.logger import init_logger


app=typer.Typer(no_args_is_help=True)
COMMAND_NAME='postex'
HELP='Authenticated SCOM inventory and command execution'

Server=Annotated[str,typer.Option('-s','--server',help='SCOM management-server hostname')]
Domain=Annotated[str,typer.Option('-d','--domain',help='Domain')]
Username=Annotated[str,typer.Option('-u','--username',help='Username')]
Password=Annotated[str,typer.Option('-p','--password',prompt='Password',hide_input=True,help='Password')]
Address=Annotated[str|None,typer.Option('-t','--target',help='Management-server IP or alternate network address')]
Port=Annotated[int,typer.Option('--port',help='SCOM DispatcherService port')]
Timeout=Annotated[int,typer.Option('--timeout',help='Per-operation network timeout in seconds')]
Verbose=Annotated[bool,typer.Option('-v','--verbose',help='Enable verbose logging')]


def _run(server,domain,username,password,address,port,timeout,verbose,**operation):
    init_logger(verbose)
    if verbose:
        os.environ['SCOM_DEBUG']='1'
    try:
        status=postex.run(server=server,address=address,port=port,domain=domain,
                          username=username,password=password,timeout=timeout,**operation)
    except Exception as exc:
        typer.echo(f'error={type(exc).__name__}: {exc}',err=True)
        raise typer.Exit(1)
    if status:
        raise typer.Exit(status)


@app.command('connect')
def connect(server:Server,domain:Domain,username:Username,password:Password,
            address:Address=None,port:Port=5724,timeout:Timeout=30,verbose:Verbose=False):
    """Authenticate and show management-group metadata."""
    _run(server,domain,username,password,address,port,timeout,verbose,connect_only=True)


@app.command('list-devices')
def list_devices(server:Server,domain:Domain,username:Username,password:Password,
                 address:Address=None,port:Port=5724,timeout:Timeout=30,verbose:Verbose=False):
    """Enumerate SCOM-managed Windows devices."""
    _run(server,domain,username,password,address,port,timeout,verbose,list_devices=True)


@app.command('find-operationsmanager')
def find_operationsmanager(server:Server,domain:Domain,username:Username,password:Password,
                           address:Address=None,port:Port=5724,timeout:Timeout=30,
                           verbose:Verbose=False):
    """Find OperationsManager web endpoints on enumerated devices."""
    _run(server,domain,username,password,address,port,timeout,verbose,
         find_operationsmanager=True)


@app.command('command')
def command(command:Annotated[str,typer.Option('-c','--command',help='cmd.exe command')],
            target_host:Annotated[str,typer.Option('--target-host',help='FQDN of the SCOM-managed device')],
            server:Server,domain:Domain,username:Username,password:Password,address:Address=None,
            port:Port=5724,timeout:Timeout=30,
            command_pack_name:Annotated[str,typer.Option('--command-pack-name',help='Command management-pack ID')]=postex.COMMAND_MP,
            no_wait:Annotated[bool,typer.Option('--no-wait',help='Return after SCOM accepts the task')]=False,
            result_timeout:Annotated[int,typer.Option('--result-timeout',help='Seconds to wait for status and output')]=330,
            verbose:Verbose=False):
    """Run a command on a SCOM-managed device and retrieve its output."""
    _run(server,domain,username,password,address,port,timeout,verbose,command=command,
         target_host=target_host,command_pack_name=command_pack_name,no_wait=no_wait,
         result_timeout=result_timeout)


@app.command('remove-command-pack')
def remove_command_pack(server:Server,domain:Domain,username:Username,password:Password,
                        address:Address=None,port:Port=5724,timeout:Timeout=30,
                        command_pack_name:Annotated[str,typer.Option('--command-pack-name',help='Command management-pack ID')]=postex.COMMAND_MP,
                        verbose:Verbose=False):
    """Remove a command management pack created by postex."""
    _run(server,domain,username,password,address,port,timeout,verbose,
         remove_command_pack=True,command_pack_name=command_pack_name)
