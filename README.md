# Ovenrack - 🍳🥧
![CI](https://github.com/ErisMik/ovenrack/workflows/Rusty/badge.svg)

"Keep your pi(e)s warm!""

## What is Ovenrack? - ⁉️
**A:** Ovenrack is a DNS proxy:
```
|Computer| <----[dns]----> |Ovenrack| <----[dns]----> |DNS Server|
```

**B:** Ovenrack can proxy tunnel the DNS over TLS (DoT):
```
|Computer| <----[dns]----> |Ovenrack| <----[DoT]----> |DNS/DoT Server|
```

**C:** Ovenrack can snoop DNS, remember the queries, and prefetch when the TTL expires:
```
|Computer| <------------------[DNS]-----------------> |DNS Server A|
                                |                            ^
                                |                            |
                                V                            |
                            |Ovenrack|------[DNS/DoT]---------
```
To keep server A warm :)

**D:** Ovenrack can snoop DNS, and forward that to another server:
```
|Computer| <------------------[DNS]-----------------> |DNS Server A|
                                |
                                |
                                V
                           |Ovenrack|----[DNS/DoT]----> |DNS Server B|
```
You know, to keep server B warm ;)

**E:** Or various combinations of the above!

## Installation - 📦
1. Download this repo
2. `cargo install`

## Usage - 🖥️
Ovenrack uses the following command line syntax:
```
Ovenrack 0.1.0
Eric M. <ericm99@gmail.com>
Keeps your pi(e)S warm!

USAGE:
    ovenrack [FLAGS] [OPTIONS] <SRC> <DEST>

FLAGS:
    -c               Enable prefetch cache
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v               Verbose output

OPTIONS:
    -p, --port <PORT>    Override the default input port [default: 53]

ARGS:
    <SRC>     Source for the requests. Using "-" inputs from stdin. See README for usage.
    <DEST>    Destination for the requests. Using "-" outputs to stdout. See README for usage.
```

SRC can be one of three formats, which dictate the behavoir:
- `-`. Takes input in from stdin.
- `DEVICE_NAME`, eg. `eno1`. Ovenrack will listen on the specified device and look for DNS traffic.
- `BIND_IP_ADDRESS`, eg. `127.0.0.1`. Ovenrack will bind to a port (default `53`) and act as a DNS server.


DEST can be one of three formats, which dictate the behavoir:
- `-`. Outputs to stdout.
- `IP_ADDR`, eg. `1.1.1.1`. Ovenrack will forward DNS traffic to the specified address as plain UDP DNS.
- `IP_ADDR#DOMAIN`, eg. `8.8.8.8#dns.google.com`. Ovenrack will forward DNS traffic to the specified address + domain as DNS over TLS.

## License - ⚖️
See [LICENSE.txt](LICENSE.txt).
