# DNS SOCKS Proxy

A simple dns proxy to tunnel DNS requests over a socks proxy (for example, over ssh or Tor). This can come in handy when setting up transparent proxies, set this as a DNS server in /etc/resolv.conf.

It chooses a random DNS server for each request from the file "resolv.conf" which is a newline delimited list of DNS servers. 

The daemon must be run as root in order for it to bind to port 53.

## Usage

Usage: ./dns-proxy [options]

With no parameters, the configuration file is read from 'dns_proxy.conf'.

* -n          -- No configuration file (socks: 127.0.0.1:9050, listener: 0.0.0.0:53).
* -h          -- Print this message and exit.
* config_file -- Read from specified configuration file.

## Configuration

The configuration file should contain any of the following options (and ignores lines that begin with '#'):

* socks_addr  -- socks listener address
* socks_port  -- socks listener port
* listen_addr -- address for the dns proxy to listen on
* listen_port -- port for the dns proxy to listen on (most cases 53)
* set_user    -- username to drop to after binding
* set_group   -- group to drop to after binding
* resolv_conf -- location of resolv.conf file to read from

Any non-specified options will be set to their defaults:

* socks_addr  = 127.0.0.1
* socks_port  = 9050
* listen_addr = 0.0.0.0
* listen_port = 53
* set_user    = nobody
* set_group   = nobody
* resolv_conf = resolv.conf

### Installation

On Arch linux, the dns proxy can be installed from the AUR at: https://aur.archlinux.org/packages/tcpdnsproxy/. The configuration file is in /etc/dns_proxy/dns_proxy.conf and the proxy can be started with:

```
systemctl start tcpdnsproxy
```

On other systems, clone the git repo  and run make.

### Credits

(c) jtRIPper 2012

http://blackhatlibrary.net/
