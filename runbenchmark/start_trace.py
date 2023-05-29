import argparse
import sys
import subprocess
import os
import signal
import glob 


# add paser logic
# python3 start_trace.py -p 1 -d /dev/sda 

parser = argparse.ArgumentParser(description='Start tracing')
parser.add_argument('-p', '--pid', type=int, help='pid to trace')
parser.add_argument('-t', '--tgid', type=int, help='tgid to trace')
parser.add_argument('-d', '--dev', type=str, help='device to trace')
parser.add_argument('-c', '--cgroup', type=str, help='cgroup to trace (only trace this cgroup)')
parser.add_argument('-f', '--file', type=int, help='the inode of file to trace (only trace this file)')
parser.add_argument('-dir', '--directory', type=int, help='the inode of directory to trace, all files of this directory will be traced')
parser.add_argument('-o', '--output', type=str, help='output file')

args = parser.parse_args()

if args.pid is not None:
    args.pid = args.pid
else:
    args.pid = None
if args.tgid is not None:
    args.tgid = args.tgid
else:
    args.tgid = None
if args.dev is not None:
    # turn dev path to dev_t 
    args.dev =  os.stat(args.dev).st_rdev
else:
    args.dev = None


# if args set the cgroup path, or cgroup id, check if the CONFIG_BLK_CGROUP is set
# first check /boot/config-$(uname -r) if CONFIG_BLK_CGROUP is set
# if not set, then check /proc/config.gz if CONFIG_BLK_CGROUP is set


bpf_compile_cmd=""

# read the pipe to get the pid of the tracer
if args.pid is not None:
    pid_filter = f"-D'TID_FILTER(x)=((x)!=({args.pid}))'"
    bpf_compile_cmd = bpf_compile_cmd + " " + pid_filter
if args.tgid is not None:
    tgid_filter = f"-D'TGID_FILTER(x)=((x)!=({args.tgid}))'"
    bpf_compile_cmd = bpf_compile_cmd + " " + tgid_filter
if args.dev is not None:
    dev_filter = f"-D'DEVICE_FILTER(x)=((x)!=({os.stat(args.dev).st_rdev}))'"
    bpf_compile_cmd = bpf_compile_cmd + " " + dev_filter
# if args.cgroup is not None:
#     # filte by cgid, get cgid from /proc/pid/cgroup ?
#     cgroup_filter = f"-DCGROUP_FILTER(x)=((x)!=)"
#     bpf_compile_cmd = bpf_compile_cmd + " " + cgroup_filter
if args.file is not None:
    # filter by file inode
    file_filter = f"-D'FILE_FILTER(x)=((x)!=({args.file}))'"
    bpf_compile_cmd = bpf_compile_cmd + " " + file_filter
if args.directory is not None:
    # filter by directory inode
    directory_filter = f"-D'DIRECTORY_FILTER(x)=((x)!=({args.directory}))'"
    bpf_compile_cmd = bpf_compile_cmd + " " + directory_filter

# Set the environment variable with the macro definitions
if os.path.exists("../build/bpf_macro_define"):
    os.system("rm ../build/bpf_macro_define")
with open("../build/bpf_macro_define", "w") as f:
    f.write(bpf_compile_cmd)

# if ../build/iotrace exist, then remove it
if os.path.exists("../build/iotrace"):
    os.system("rm ../build/iotrace")
os.system("bash -c 'pushd ../build && make -j8 && cp iotrace ../run && popd' ")


# traceProc = subprocess.Popen(['sudo', './iotrace'], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
traceProc = subprocess.Popen(['sudo', './iotrace'])
print("start tracing")
# handle SIGINT 
def signal_handler(sig, frame):
    print(f'You pressed Ctrl+C and kill the trace process :{traceProc.pid}')
    subprocess.run(['sudo', 'pkill', '-P', str(traceProc.pid)])
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)
traceProc.wait()


        