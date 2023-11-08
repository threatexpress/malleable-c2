# Cobalt Strike Malleable C2 Design and Reference Guide

This project is intended to serve as reference when designing Cobalt Strike Malleable C2 profiles.

Always verify your profile with `./c2lint [/path/to/my.profile]` prior to use!

## Malleable C2 Profile Guidance

The following dive deeper into the understanding of Malleable C2

- [MalleableExplained.md](https://github.com/threatexpress/malleable-c2/blob/master/MalleableExplained.md) : Quick profile reference guide
- [ThreatExpress - A Deep Dive into Cobalt Strike Malleable C2](http://threatexpress.com/blogs/2018/a-deep-dive-into-cobalt-strike-malleable-c2/) : Orignal blog post the where the jquery reference profile was created
- [Understanding Cobalt Strike Profiles](https://blog.zsec.uk/cobalt-strike-profiles/) : Revised (current) blog on profile guidance
- [Random Profile Generator](https://github.com/threatexpress/random_c2_profile) : Profile generator with more examples and options for settings

## Changelog

### 20231017 - Updated for CS 4.9
- Added 4.9 reference profile
- Updated MalleableExplained.md with new 4.9 options
  - `post-ex.cleanup`
  - `.http-beacon.library`

### 20230801 - Updated for CS 4.8
- Added 4.8 reference profile
- Updated MalleableExplained.md with new 4.8 options
  - `stage.syscall_method`

### 20221022 - Updated for CS 4.7
- Added 4.7 reference profile
- Updated MalleableExplained.md with 4.7 considerations

### 20220421 - Updated for CS 4.6
- Added 4.6 reference profile
- No more '1MB' limit
  - Add section "Task and Proxy Max Size" with new options
    - set tasks_max_size "1048576";
    - set tasks_proxy_max_size "921600";
    - set tasks_dns_proxy_max_size "71680";  
  - [Additional Considerations for the 'task_' Settings](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_profile-language.htm#_Toc65482837)
- Updated MalleableExplained.md with 4.6 considerations

### 202112 - Updated for CS 4.5
- Added 4.5 reference profile
- Updated MalleableExplained.md with 4.5 considerations

### 202108 - Added [MalleableExplained.md](https://github.com/threatexpress/malleable-c2/blob/master/MalleableExplained.md) 
- Reference from Andy Gill (@ZephrFish)
- Reference blog: https://blog.zsec.uk/cobalt-strike-profiles/

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
- @Charles-Foster-Kane

## License

This project and all individual scripts are under the GNU GPL v3.0 license.

