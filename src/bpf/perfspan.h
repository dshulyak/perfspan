#ifndef __PROFILE_H_
#define __PROFILE_H_

#ifndef MAX_NAME_SIZE
#define MAX_NAME_SIZE 128
#endif

#ifndef MAX_EVENTS
#define MAX_EVENTS 2
#endif

const __u8 ENTER = 0;
const __u8 EXIT = 1;

struct event 
{
    __u8 type;
    __u8 name_id;
    __u16 cpu;
    __u64 span_id;
    __u64 pid_tgid;
    __u64 timestamp;
    __u64 counters[MAX_EVENTS];
};

#endif