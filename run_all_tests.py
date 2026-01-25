import subprocess

RED = "\033[31m"
RESET = "\033[0m"

cmd = ["python", "run_some_tests.py", "-which", "MemoryManagement", "-v", "-o", "-r", "-b", "-HMM"]
print(RED + str(cmd) + RESET)
proc = subprocess.run(cmd)
cmd = ["python", "run_some_tests.py", "-which", "MemoryManagement", "-v", "-o", "-r", "-b", "-c", "-HMM"]
print(RED + str(cmd) + RESET)
proc = subprocess.run(cmd)
cmd = ["python", "run_some_tests.py", "-which", "MemoryUsage", "-v", "-o", "-r", "-b", "-HMM", "-HMU_ord"]
print(RED + str(cmd) + RESET)
proc = subprocess.run(cmd)
cmd = ["python", "run_some_tests.py", "-which", "MemoryUsage", "-v", "-o", "-r", "-b", "-c", "-HMM", "-HMU_ord"]
print(RED + str(cmd) + RESET)
proc = subprocess.run(cmd)
cmd = ["python", "run_some_tests.py", "-which", "MemoryUsage", "-v", "-o", "-r", "-b", "-HMM", "-HMU_unord"]
print(RED + str(cmd) + RESET)
proc = subprocess.run(cmd)
cmd = ["python", "run_some_tests.py", "-which", "MemoryUsage", "-v", "-o", "-r", "-b", "-c", "-HMM", "-HMU_unord"]
print(RED + str(cmd) + RESET)
proc = subprocess.run(cmd)