#!/usr/bin/env python
from bcc import BPF

bpf_source = """
BPF_HASH(exec_count);

int count_execve(void *ctx) {
	u64 key = 0;
	u64 *count = exec_count.lookup(&key);
	if (count) {
			(*count)++;
	} else {
			u64 new_count = 1;
			exec_count.update(&key, &new_count);
	}
	return 0;
}
"""

b = BPF(text=bpf_source)
b.attach_kprobe(event=b.get_syscall_fnname("execve"),fn_name="count_execve")

print("Tracing execve() calls... Hit Ctrl+C to stop.")

try:
	while True:
		pass
except KeyboardInterrupt:
	pass

print("")
for key, value in b.get_table("exec_count").items():
	print(f"execve() was called {value.value} times.")
