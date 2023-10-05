---
title: A macOS anti-debug technique using ptrace
description: A subtlety of the ptrace system call can be used to prevent a program from being debugged on macOS.
tags: [macOS, ptrace, dtrace, lldb, dyld, debug]
---

This post was initially a StackOverflow [answer] for a question which I stumbled upon when trying to reverse a macOS Objective-C executable (henceforth, `the-program`) and faced, apparently, the same issue.

[answer]: https://stackoverflow.com/a/47755340/477168

## The problem

Said program simply exits when run with a debugger and all the common-sense approaches fail: breaking on the *exit* function, checking signals, etc. leaving us with the following enigmatic output:

```
$ lldb the-program
(lldb) run
Process 8151 launched: '/path/to/the-program' (x86_64)
Process 8151 exited with status = 45 (0x0000002d)
```

## Figuring out what happens here

Running it through `dtruss` does not trigger the protection, so one can run it with `lldb` then attach to the process with `dtruss` like this:

```
(lldb) process launch --stop-at-entry
Process 8160 stopped
* thread #1, stop reason = signal SIGSTOP
    frame #0: 0x000000010146f19c dyld`_dyld_start
dyld`_dyld_start:
->  0x10146f19c <+0>: popq   %rdi
    0x10146f19d <+1>: pushq  $0x0
    0x10146f19f <+3>: movq   %rsp, %rbp
    0x10146f1a2 <+6>: andq   $-0x10, %rsp
Target 0: (dyld) stopped.
Process 8160 launched: '/path/to/the-program' (x86_64)
```

Then from another terminal:

```
$ dtruss -p 8160
```

Finally issuing a `continue` to `lldb` allows to inspect all the system calls, but again no luck, no `exit` or otherwise suspicious invocations.

But there *must* be a system call, right? So I thought maybe (unlike `strace` for Linux) `exit` invocations are not reported since they does not actually return. So I decided to write a DTrace script to hook at the *entry* to each system call and run the program with `lldb` as above:

```console
# dtrace -q -n 'syscall:::entry /pid == $target/ { printf("%s\n", probefunc); }' -p <pid>

[...]
mmap
close
workq_kernreturn
open
read
close
open
read
close
ptrace
```

Now `ptrace` *is* suspicious since it is what debuggers normally use, in fact digging into the manual there is the even more suspicious `PT_DENY_ATTACH` request:

> This request is the other operation used by the traced process; it allows a process that is not currently being traced to deny future traces by its parent. All other arguments are ignored. If the process is currently being traced, it will exit with the exit status of ENOTSUP; otherwise, it sets a flag that denies future traces. An attempt by the parent to trace a process which has set this flag will result in a segmentation violation in the parent.

And from `errno.h`[^errno] we can learn that `ENOTSUP` is actually `45`! Notice also how the last sentence basically tells us that we cannot attach a debugger to a running instance of our program.

[^errno]: Full path is `/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/sys/errno.h`.

So this is definitely what causes our program to prematurely exit.

## Bypassing the `ptrace` invocation

Unfortunately though, in our executable there is no import symbol for `ptrace` so we cannot set a breakpoint on it. This might be the case if the system call is invoked from an inline assembly block.

Moreover, it happens that there is no `main` or similar entry points pointing to the program code, we can only start the debugger from the first instruction which is part of `dyld`, the dynamic linker. Any attempt to break once the instruction pointer enters the actual program code fails, so the check must be performed by the the linker during the initialization phase. This can be accomplished in C/C++ by annotating a function function with `__attribute__((constructor))` or in the case of Objective-C using the `+load` method.

DTrace comes to the rescue again by allowing to print the stack trace when the `ptrace` system call is entered:

```console
# dtrace -q -n 'syscall:::entry /pid == $target && probefunc == "ptrace"/ { ustack(); }' -p <pid>

the-program`0x1000b6162
the-program`0x1000b6e02
libobjc.A.dylib`load_images+0x46
dyld`dyld::notifySingle(dyld_image_states, ImageLoader const*, ImageLoader::InitializerTimingList*)+0x197
dyld`ImageLoader::recursiveInitialization(ImageLoader::LinkContext const&, unsigned int, char const*, ImageLoader::InitializerTimingList&, ImageLoader::UninitedUpwards&)+0x135
dyld`ImageLoader::processInitializers(ImageLoader::LinkContext const&, unsigned int, ImageLoader::InitializerTimingList&, ImageLoader::UninitedUpwards&)+0x86
dyld`ImageLoader::runInitializers(ImageLoader::LinkContext const&, ImageLoader::InitializerTimingList&)+0x4a
dyld`dyld::initializeMainExecutable()+0xc4
dyld`dyld::_main(macho_header const*, unsigned long, int, char const**, char const**, char const**, unsigned long*)+0x1c4a
dyld`dyldbootstrap::start(macho_header const*, int, char const**, long, macho_header const*, unsigned long*)+0x1c5
dyld`_dyld_start+0x36
the-program`0x1
```

This confirms that `ptrace` is invoked by a library *initializer* function and `0x1000b6162` denotes the return address of the system call, so the breakpoint must be set 2 bytes before that (thus skipping the `syscall` instruction, opcode `0f05`). Unfortunately `lldb` is not able to set such breakpoint, I guess this is because there is another trick in place, but IDA can do that.

From now on one could simply skip/nop that call to see what lies ahead... which in the case of `the-program`, was a bunch of other checks and obfuscated assembly.

## Reproducing the technique

Now it would be nice to be able to put all together and write a minimal program that implements this technique:

```objc
#import <Foundation/Foundation.h>

@interface Foo : NSObject
@end

@implementation Foo

+(void)load {
    NSLog (@"-- LOAD");

    asm("movq $0, %rcx");
    asm("movq $0, %rdx");
    asm("movq $0, %rsi");
    asm("movq $0x1f, %rdi");      /* PT_DENY_ATTACH 31 (0x1f)*/
    asm("movq $0x200001a, %rax"); /* ptrace syscall number 26 (0x1a) */
    asm("syscall");
}

@end

int main (int argc, const char * argv[]) {
    NSLog (@"-- MAIN");
    return 0;
}
```

Compile with:

```console
$ clang -framework Foundation anti-debug.m -o anti-debug
```

Then:

```console
$ ./anti-debug
2018-02-10 21:59:32.638 anti-debug[4602:81365] -- LOAD
2018-02-10 21:59:32.638 anti-debug[4602:81365] -- MAIN

$ lldb ./anti-debug
(lldb) run
Process 4605 launched: './anti-debug' (x86_64)
2018-02-10 21:59:50.732396+0100 anti-debug[4605:81479] -- LOAD
Process 4605 exited with status = 45 (0x0000002d)
```

### System call number

Just a note about the system call number, according to [`syscalls.master`] the number is `26` but [`syscall_sw.h`] defines that:

```c
#define SYSCALL_CLASS_SHIFT	24
#define SYSCALL_CLASS_MASK	(0xFF << SYSCALL_CLASS_SHIFT)
#define SYSCALL_NUMBER_MASK	(~SYSCALL_CLASS_MASK)

#define SYSCALL_CLASS_UNIX	2	/* Unix/BSD */

#define SYSCALL_CONSTRUCT_UNIX(syscall_number) \
			((SYSCALL_CLASS_UNIX << SYSCALL_CLASS_SHIFT) | \
			 (SYSCALL_NUMBER_MASK & (syscall_number)))
```

Doing the math we obtain `0x200001a`.

[`syscalls.master`]: https://opensource.apple.com/source/xnu/xnu-4570.1.46/bsd/kern/syscalls.master
[`syscall_sw.h`]: https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/i386/syscall_sw.h
