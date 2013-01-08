# DNS SOCKS Proxy

A simple dns proxy to tunnel DNS requests over a socks proxy (for example, over ssh or Tor). This can come in handy when setting up transparent proxies, set this as a DNS server in /etc/resolv.conf.

## Usage

Usage: ./dns-proxy [options]

With no parameters, the configuration file is read from 'dns.conf'.

* -n          -- No configuration file (socks: 127.0.0.1:9999, listener: 0.0.0.0:53).
* -h          -- Print this message and exit.
* config_file -- Read from specified configuration file.\n

## Configuration

The configuration file should contain any of the following options (and ignores lines that begin with '#'):

* socks_addr  -- socks listener address
* socks_port  -- socks listener port
* listen_addr -- address for the dns proxy to listen on
* listen_port -- port for the dns proxy to listen on (most cases 53)

Any non-specified options will be set to their defaults:

* socks_addr = 127.0.0.1
* socks_port = 9999
* listen_addr = 0.0.0.0
* listen_port = 53

### Credits

(c) jtRIPper 2012
