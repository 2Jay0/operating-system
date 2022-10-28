# Operating-system
> 2021 - pintos project

## Duration
> 2021.09. ~ 2021.12.

## About Project
### Project 1. User Program(1)
* Argument Parsing
* User Memory Access
* System Call

### Project 2. User Program(2)
* File Descriptor
* System Call
* Synchronization in File System

### Project 3. Threads
* Alarm Clock
* Prioirty Scheduling
* Advanced Scheduler

### Project 4. Virtual Memoey
* Page Table & Page Fault Handler
* Disk Swap
* Stack Growth

### Project 5. File System
* Extensible File & File Growth
* Subdirectory
* Buffer Cache

## Project Content
### Pintos OS
* 초기 Pintos는 간단한 OS Framework로 booting, application 실행, power off 만 가능
### System Call
* Pintos 환경에서 입력 받은 Argument를 Parse해 User Stack에 쌓고 메모리에 access할 때 parse한 명령어 중 전달 받은 주소 값이 적절한 공간을 사용하는지 확인하는 작업을 수행
* System Call인 halt, exit, exec, write, read 명령어를 각각 구현
### Thread Scheduling
* Blocked 상태의 thread를 깨우기 위해 timer interrupt에서 깨울 thread가 있다면 unblock함수를 통해 unblock 후 list에 thread를 remove하는 방식을 추가
* 기존의 scheduling 방식일 때 한 thread가 cpu를 독식하는 문제를 해결하기 위해 Priority Scheduling으로 변경했고 추가로 효율적인 MLFQS를 구현
### Virtual Machine
* Physical 메모리에서 벗어난 공간을 사용했을 때 가상 메모리 공간인 virtual memory를 구현해 page table을 만들어서 page fault를 처리
* 메모리 공간이 부족하다면 LRU 알고리즘 기반으로 Disk를 구현
### File System
* Disk에서 비효율적으로 block을 read, write한 것을 buffer cache를 구현해 효율성 보장

## Technology Stack
C, Data Structure(List, Hash Table, Bitmap)
