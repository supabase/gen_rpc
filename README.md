# gen_rpc: A scalable RPC library for Erlang-VM based languages [![Run test case](https://github.com/emqx/gen_rpc/actions/workflows/run_test_case.yaml/badge.svg?branch=master)](https://github.com/emqx/gen_rpc/actions/workflows/run_test_case.yaml)

## Overview

- [Erlang Factory 2016 Talk](https://www.youtube.com/watch?feature=player_embedded&v=xiPnLACtNeo)

## Build Dependencies

To build this project you need to have the following:

* **Erlang/OTP** >= 19.1

* **git** >= 1.7

* **GNU make** >= 3.80

* **rebar3** >= 3.2

## Usage

Getting started with `gen_rpc` is easy. First, add the appropriate dependency line to your `rebar.config`:

```erlang
{deps, [
    {gen_rpc, {git, "https://github.com/emqx/gen_rpc.git", {branch, "master"}}}
]}.
```

Or if you're using `hex.pm`/`rebar3`:

```erlang
{deps [
    {gen_rpc, "~> 2.0"}
]}.
```

Or if you're using Elixir/Mix:

```elixir
def project do
  [
    deps: [
      {:gen_rpc, "~> 2.0"}
    ]
  ]
```

Then, add `gen_rpc` as a dependency application to your `.app.src`/`.app` file:

```erlang
{application, my_app, [
    {applications, [kernel, stdlib, gen_rpc]}
]}
```

Or your `mix.exs` file:

```elixir
def application do
  applications: [:gen_rpc]
end
```

Finally, start a couple of nodes to test it out:

```erlang
(my_app@127.0.0.1)1> gen_rpc:call('other_node@1.2.3.4', erlang, node, []).
'other_node@1.2.3.4'
```
## API

`gen_rpc` implements only the subset of the functions of the `rpc` library that make sense for the problem it's trying to solve. The library's function interface and return values is **100%** compatible with `rpc` with only one addition: Error return values include `{badrpc, Error}` for RPC-based errors but also `{badtcp, Error}` for TCP-based errors.

For more information on what the functions below do, run `erl -man rpc`.

### Functions exported

- `call(NodeOrNodeAndKey, Module, Function, Args)` and `call(NodeOrNodeAndKey, Module, Function, Args, Timeout)`: A blocking synchronous call, in the `gen_server` fashion.

- `cast(NodeOrNodeAndKey, Module, Function, Args)`: A non-blocking fire-and-forget call.

- `async_call(NodeOrNodeAndKey, Module, Function, Args)`, `yield(Key)`, `nb_yield(Key)` and `nb_yield(Key, Timeout)`: Promise-based calls. Make a call with `async_call` and retrieve the result asynchronously, when you need it with `yield` or `nb_yield`.

- `multicall(Module, Function, Args)`, `multicall(Nodes, Module, Function, Args)`, `multicall(Module, Function, Args, Timeout)` and `multicall(NodesOrNodesWithKeys, Module, Function, Args, Timeout)`: Multi-node version of the `call` function.

- `abcast(NodesOrNodesWithKeys, Name, Msg)` and `abcast(Name, Msg)`: An asynchronous broadcast function, sending the message `Msg` to the named process `Name` in all the nodes in `NodesOrNodesWithKeys`.

- `sbcast(NodesOrNodesWithKeys, Name, Msg)` and `sbcast(Name, Msg)`: A synchronous broadcast function, sending the message `Msg` to the named process `Name` in all the nodes in `NodesOrNodesWithKeys`. Returns the nodes in which the named process is alive and the nodes in which it isn't.

- `eval_everywhere(Module, Function, Args)` and `eval_everywhere(NodesOrNodesWithKeys, Module, Function, Args)`: Multi-node version of the `cast` function.

### Per-Key Sharding

`gen_rpc` supports multiple outgoing connections per node using a key of arbitrary type to differentiate between connections.
To leverage this feature, replace `Node` in your calls (**single-node** and **multi-node** alike) with `{Node, Key}`. The `Key` is hashed using `erlang:phash2/1`, attached to the client process name and a new connection is initiated.

**Attention:** When using functions that call `gen_rpc:nodes/0` implicitly (such as `gen_rpc:multicall/3`), the channels
used to communicate to the nodes are the **keyless** ones. To leverage the sharded functionality, pre-create your `{Node, Key}` lists
and pass them as the node list in the multi-node function.

### Module version control

`gen_rpc` supports executing RPC calls on remote nodes that are running only specific module versions. To leverage that feature, in place of `Module` in the section above, use `{Module, Version}`. If the remote `module` is not on the version requested a `{badrpc,incompatible]` will be returned.

## Application settings

- `port_discovery`:

    The strategy for getting the listening port of local node. Defaults to `manual`.

    - Set it to `manual` (default) the gen_rpc will resolve the listening ports by `tcp_server_port`, `ssl_server_port`, `tcp_client_port` and `ssl_client_port`.

    - Set it to `stateless` the gen_rpc will resolve the listening prot by node name with a stateless approach:
    If node name is `emqx<N>@127.0.0.1` where the `<N>` is an integer, then the listening port will be `5370 + <N>`.
    e.g.
      1. node_name = `emqx@127.0.0.1`:
        port = 5370
      2. node_name = `emqx3@127.0.0.1`:
        port = 5373
      3. node_name = `emqx60165@127.0.0.1`:
        port = 65535
      4. node_name = `emqx60166@127.0.0.1`:
        invalid and gen_rpc cannot get started
- `compress`: A number (default = 0) from 0 to 9 to define level of compression.

- `compression_threshold`: The minimum amount of bytes (default = 1024) needed to be worth compressing the TCP message sent.

- `dispatcher_pool_size`: Number of `gen_rpc_dispatcher`s to start new clients.

- `tcp_server_port`: The plain TCP port `gen_rpc` will use for incoming connections or `false` if you
  do not want plain TCP enabled. Only takes effect when `port_discovery` = `manual`.

- `tcp_client_port`: The plain TCP port `gen_rpc` will use for outgoing connections. Only takes effect when `port_discovery` = `manual`.

- `ssl_server_port`: The port `gen_rpc` will use for incoming SSL connections or `false` if you do not
  want SSL enabled. Only takes effect when `port_discovery` = `manual`.

- `ssl_client_port`: The port `gen_rpc` will use for outgoing SSL connections. Only takes effect when `port_discovery` = `manual`.

- `ssl_server_options` and `ssl_client_options`: Settings for the `ssl` interface that `gen_rpc` will use to
  connect to a remote `gen_rpc` server.

- `default_client_driver`: The default driver `gen_rpc` is going to use to connect to remote `gen_rpc` nodes.
  It should be either `tcp` or `ssl`.

- `client_config_per_node`: A map of `Node => {Driver, Port}` or `Node => Port` that instructs `gen_rpc` on the `Port`
  and/or `Driver` to use when connecting to a `Node`. If you prefer to use an external discovery service to map `Nodes`
  to `{Driver, Port}` tuples, instead of the map, you'll need to define a `{Module, Function}` tuple instead with a function
  that takes the `Node` as its single argument, consumes the external discovery service and returns a `{Driver, Port}` tuple.

- `rpc_module_control`: Set it to `blacklist` to define a list of modules that will not be exposed to `gen_rpc` or to `whitelist`
  to define the list of modules that will be exposed to `gen_rpc`. Set it to `disabled` to disable this feature.

- `rpc_module_list`: The list of modules that are going to be blacklisted or whitelisted.

- `authentication_timeout`: Default timeout for the authentication state of an incoming connection in **milliseconds**.
  Used to protect against half-open connections in a DoS attack.

- `connect_timeout`: Default timeout for the initial node-to-node connection in **milliseconds**.

- `send_timeout`: Default timeout for the transmission of a request (`call`/`cast` etc.) from the local node to the remote node in **milliseconds**.

- `call_receive_timeout`: Default timeout for the reception of a response in a `call` in **milliseconds**.

- `sbcast_receive_timeout`: Default timeout for the reception of a response in an `sbcast` in **milliseconds**.

- `client_inactivity_timeout`: Inactivity period in **milliseconds** after which a client connection to a node will be closed (and hence have the TCP file descriptor freed).

- `server_inactivity_timeout`: Inactivity period in **milliseconds** after which a server port will be closed (and hence have the TCP file descriptor freed).

- `async_call_inactivity_timeout`: Inactivity period in **milliseconds** after which a pending process holding an `async_call` return value will exit. This is used for process sanitation purposes so please make sure to set it in a sufficiently high number (or `infinity`).

- `socket_keepalive_idle`: Seconds idle after the last packet of data sent to start sending keepalive probes (applies to both drivers).

- `socket_keepalive_interval`: Seconds between keepalive probes.

- `socket_keepalive_count`: Probs lost to consider the socket closed

- `socket_ip`: A IP-tuple like `{0,0,0,0}` (default, IPv4) or `{0,0,0,0,0,0,0,0}` (IPv6) for listener to listen on. Values other than a 4-tuple or a 8-tuple are silently discarded.

- `ipv6_only`: Boolean (default = false) to force server and client to use ipv6. This config only takes effect when `socket_ip` is a 8-tuple (IPv6).

- `acceptor_socket_active_n`: Integer (default = 100) for RPC acceptor flow control.

## SSL Configuration

`gen_rpc` supports SSL for inter-node communication. This allows secure communication and execution over insecure channels such as the internet, essentially allowing a **trully globally distributed Erlang/Elixir** setup. `gen_rpc` is very opinionated on how SSL should be configured and the bundled default options include:

- A proper PFS-enabled cipher suite

- Both server and client-based SSL node CN (Common Name) verification

- Secure renegotiation

- TLS 1.1/1.2 enforcement

All of these settings can be found in `include/ssl.hrl` and overriden by redefining the necessary option in `ssl_client_options` and `ssl_server_options`. To actually use SSL support, you'll need to define in both `ssl_client_options` and `ssl_server_options`:

- The public and private keys in PEM format, for the node you're running `gen_rpc` on, using the usual `certfile`, `keyfile` options.

- The public key of the CA that signs the node's key and the public key(s) of CA that `gen_rpc` should trust, included in the file `cacertfile` points at.

- Optionally, a Diffie-Hellman parameter file using the `dhfile` option.

To generate your own self-signed CA and node certificates, numerous articles can be found online such as [this](https://help.github.com/enterprise/11.10.340/admin/articles/using-self-signed-ssl-certificates/).

Usually, the CA that will be signing your client and server SSL certificates will be the same so a nominal `sys.confg` that includes SSL support for `gen_rpc` will look like:

```erlang
    {gen_rpc, [
        {ssl_client_options, [
            {certfile, "priv/cert.pem"},
            {keyfile, "priv/cert.key"},
            {cacertfile, "priv/ca.pem"},
            {dhfile, "priv/dhparam.pem"}
        ]},
        {ssl_server_options, [
            {certfile, "priv/cert.pem"},
            {keyfile, "priv/cert.key"},
            {cacertfile, "priv/ca.pem"},
            {dhfile, "priv/dhparam.pem"}
        ]}
    ]}
```

For multi-site deployments, a performant setup can be provisioned with edge `gen_rpc` nodes using SSL over the internet and plain TCP for internal data exchange. In that case, non-edge nodes can have `{ssl_server_port, false}` and `{default_client_driver, tcp}` and edge nodes can have their plain TCP port firewalled externally and `{default_client_driver, ssl}`.

## External Source Support

`gen_rpc` can call an external module to provide driver/port mappings in case you want to use an external discovery service like `etcd`
for node configuration management. The module should implement the `gen_rpc_external_source` behaviour which takes the `Node` as an argument and should return either `{Driver, Port}` (`Driver` being `tcp` or `ssl` and `Port` being the port the remote node's
`gen_rpc`'s driver is listening in) or `{error, Reason}` (if the service is unavailable). To set it, change `client_config_per_node` from the default of `{internal, #{}}` to `{external, ModuleName}` where `ModuleName` is the module that implements the `gen_rpc_external_source` behaviour.

## Build Targets

`gen_rpc` bundles a `Makefile` that makes development straightforward.

To build `gen_rpc` simply run:

    make

To run the full test suite, run:

    make test

To run the full test suite, the XRef tool and Dialyzer, run:

    make dist

To build the project and drop in a console while developing, run:

    make shell-master

or

    make shell-slave

If you want to run a "master" and a "slave" `gen_rpc` nodes to run tests.

To clean every build artifact and log, run:

    make distclean

## Testing

A full suite of tests has been implemented for `gen_rpc`. You can run the CT-based test suite, dialyzer and xref by:

    make dist

If you have **Docker** available on your system, you can run dynamic integration tests with "physically" separated hosts/nodes
by running the command:

    make integration

This will launch 3 slave containers and 1 master (change that by `NODES=5 make integration`) and will run the `integration_SUITE` CT test suite.

## Rationale

**TL;DR**: `gen_rpc` uses a mailbox-per-node architecture and `gen_tcp` processes to parallelize data reception from multiple nodes without blocking the VM's distributed port.

The reasons for developing `gen_rpc` became apparent after a lot of trial and error while trying to scale a distributed Erlang infrastructure using the `rpc` library initially and subsequently `erlang:spawn/4` (remote spawn). Both these solutions suffer from very specific issues under a sufficiently high number of requests.

The `rpc` library operates by shipping data over the wire via Distributed Erlang's ports into a registered `gen_server` on the other side called `rex` (Remote EXecution server), which is running as part of the standard distribution. In high traffic scenarios, this allows the inherent problem of running a single `gen_server` server to manifest: mailbox flooding. As the number of nodes participating in a data exchange with the node in question increases, so do the messages that `rex` has to deal with, eventually becoming too much for the process to handle (don't forget this is confined to a single thread).

Enter `erlang:spawn/4` (_remote spawn_ from now on). Remote spawn dynamically spawns processes on a remote node, skipping the single-mailbox restriction that `rex` has. The are various libraries written to leverage that loophole (such as [Rexi](https://github.com/cloudant/rexi)), however there's a catch.

Remote spawn was not designed to ship large amounts of data as part of the call's arguments. Hence, if you want to ship a large binary such as a picture or a transaction log (large can also be small if your network is slow) over remote spawn, sooner or later you'll see this message popping up in your logs if you have subscribed to the system monitor through `erlang:system_monitor/2`:

```erlang
{monitor,<4685.187.0>,busy_dist_port,#Port<4685.41652>}
```

This message essentially means that the VM's distributed port pair was busy while the VM was trying to use it for some other task like _Distributed Erlang heartbeat beacons_ or _mnesia synchronization_. This of course wrecks havoc in certain timing expectations these subsystems have and the results can be very problematic: the VM might detect a node as disconnected even though everything is perfectly healthy and `mnesia` might misdetect a network partition.

`gen_rpc` solves both these problems by sharding data coming from different nodes to different processes (hence different mailboxes) and by using a different `gen_tcp` port for different nodes (hence not utilizing the Distributed Erlang ports).

## Architecture

In order to achieve the mailbox-per-node feature, `gen_rpc` uses a very specific architecture:

- Whenever a client needs to send data to a remote node, it will perform a `whereis` to a process named after the remote node.

- If the specified `client` process does not exist, it will request for a new one through the `dispatcher` pool of processes, which in turn will launch it through the appropriate `client` supervisor. Since this |`whereis` > request from dispatcher sequence > start client| can happen concurrently by many different processes, serializing it behind a `gen_server` allows us to avoid race conditions.

- The `dispatcher` process will launch a new `client` process through the client's supervisor.

- The new client process will connect to the remote node's `gen_rpc server`, submit a request for a new server and wait.

- The `gen_rpc server` server will ask the `acceptor` supervisor to launch a new `acceptor` process and hands it off the new socket connection.

- The `acceptor` takes over the new socket and authenticates the `client` with the current Erlang cookie and any extra protocol-level authentication supported by the selected driver.

- The `client` finally encodes the request (`call`, `cast` etc.) along with some metadata (the caller's PID and a reference) and sends it over the TCP channel. In case of an `async call`, the `client` also launches a process that will be responsible for handing the server's reply to the requester.

- The `acceptor` on the other side decodes the TCP message received and spawns a new process that will perform the requested function. By spawning a process external to the server, the `acceptor` protects itself from misbehaving function calls.

- As soon as the reply from the server is ready (only needed in `async_call` and `call`), the `acceptor` spawned process messages the server with the reply, the `acceptor` ships it through the TCP channel to the `client` and the client send the message back to the requester. In the case of `async call`, the `client` messages the spawned worker and the worker replies to the caller with the result.

All `gen_tcp` processes are properly linked so that any TCP failure will cascade and close the TCP channels and any new connection will allocate a new process and port.

An inactivity timeout has been implemented inside the `client` and `server` processes to free unused TCP connections after some time, in case that's needed.

## Performance

`gen_rpc` is being used in production extensively with over **150.000 incoming calls/sec/node** on a **8-core Intel Xeon E5** CPU and **Erlang 19.1**. The median payload size is **500 KB**. No stability or scalability issues have been detected in over a year.

## Known Issues

- When shipping an anonymous function over to another node, it will fail to execute because of the way Erlang implements anonymous functions (Erlang serializes the function metadata but not the function body). This issue also exists in both `rpc` and remote spawn.

## Licensing

This project is published and distributed under the [Apache License](LICENSE).

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md)

### Contributors:

- [Edward Tsang](https://github.com/linearregression)
