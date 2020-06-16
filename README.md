# Ovenrack - 🍳🥧
"Keep your pi(e)s warm!""
![CI](https://github.com/ErisMik/ovenrack/workflows/Rusty/badge.svg)

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


## License - ⚖️
Coming Soon (TM)
