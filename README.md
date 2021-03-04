# Cobalt Strike Malleable C2 Design and Reference Guide

This project is intended to serve as reference when designing Cobalt Strike Malleable C2 profiles.

Always verify your profile with `./c2lint [/path/to/my.profile]` prior to use!

## Changelog

### 202103 - Add CS 4.3 Reference Profile

- Add latest Malleable C2 profile options for Cobalt Strike 4.3
- Moved dns settings to new `dns-beacon` section
- 4.3 Additions
  - **dns-beacon**
    - beacon
    - get_A
    - get_AAAA
    - get_TXT
    - put_metadata
    - put_output
    - ns_response
  - **http-config**
    - block_useragents

### 202011 - Add CS 4.2 Reference Profile

- Add latest MalleablePE and MalleableC2 options for Cobalt Strike 4.1 and 4.2
- 4.1 Additions: `tcp_frame_header`, `smb_frame_header`, `ssh_banner`
- 4.2 Additions:
  - **global**
    - `data_jitter`
    - `headers_remove`
    - `ssh_pipename`
  - **postex**
     - `pipename`
     - `thread_hint`
     - `keylogger`
  - **stage**
    - `allocator`
    - `magic_mz_86|magic_mz_64`
    - `magic_pe`

### 202003 - CS 4.0 Reference Profile

- Add CS4.0 reference profile of available malleable C2 options
- Remove deprecated features (`amsi_disable`, `disable` for process injection techniques, etc)

## Authors

- @joevest
- @001SPARTaN
- @andrewchiles

## License

This project and all individual scripts are under the GNU GPL v3.0 license.

## Links

[ThreatExpress - A Deep Dive into Cobalt Strike Malleable C2](http://threatexpress.com/blogs/2018/a-deep-dive-into-cobalt-strike-malleable-c2/)