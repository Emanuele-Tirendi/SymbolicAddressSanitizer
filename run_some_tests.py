import os
import subprocess
import argparse
import detector
import shadow
import sys

VERBOSE = False
OUTPUT = False
BUILD = False
RUN = False
HMM = False
HMU_ord = False
HMU_unord = False
CONCRETIZE = False

def output(s):
    if OUTPUT or VERBOSE:
        print(f"o: {s}")
    
def verbose(s):
    if VERBOSE:
        print(f"v: {s}")

def get_filename(category, symb_or_conc, correct_or_incorrect, number):
    return f"tests/{category}/{symb_or_conc}/{correct_or_incorrect}/{number}/test{number}.cpp"

def get_binname(category, symb_or_conc, correct_or_incorrect, number):
    return f"tests/{category}/{symb_or_conc}/{correct_or_incorrect}/{number}/test{number}.exe"

def get_error_message(modulename):
    return f"Assertion error for {modulename}"

def remove_file(binname):
    if os.path.exists(binname):
        verbose(f"Removing existing file: {binname}")
        try:
            os.remove(binname)
        except Exception as e:
            raise RuntimeError(f"Failed to remove {binname}: {e}") from e
    else:
        verbose("no file to remove")

# check if the detector worked correctly in given test run
def check(found, simgr, proj, error, correct_or_incorrect):

    # check if the only stashes containing states are 'vuln' and 'deadended'
    assert simgr.pruned==[], error
    try:
        assert simgr.errored==[], error
    except Exception as e:
        print(f"Exception {e}\n \
Error of errored state is {simgr.errored[0].error}")
        sys.exit()
    assert simgr.unconstrained==[], error
    assert simgr.unsat==[], error
    assert simgr.active==[], error

    # check if detector didn't detect false positives or false negatives
    if correct_or_incorrect == "Correct":
        assert not found, error
    else:
        assert found, error
        to_reach = False
        not_to_reach = True

        # check if the vulnerability detected was detected at the right line of code
        cfg = proj.analyses.CFGFast()
        # get addresses of functions 'to_reach' and 'not_to_reach'
        to_reach_fun = cfg.kb.functions.function(name="__Z8to_reachv")
        not_to_reach_fun = cfg.kb.functions.function(name="__Z12not_to_reachv")
        # check for occurence of function calls to mentioned functions in the history plugin
        for descr in simgr.vuln[0].history.descriptions:
            if str(hex(to_reach_fun.addr)) in descr:
                to_reach = True
            if str(hex(not_to_reach_fun.addr)) in descr:
                print("Here")
                not_to_reach = False
        assert to_reach, error # assert that function 'to_reach' has been reached
        assert not_to_reach, error # assert that function 'not_to_reach' has not been reached

def bytes_to_int(byte_sequence):
    byte_str = byte_sequence.decode('utf-8')
    return int(byte_str)

def run_vulnerability(simgr, binname):
    if not RUN:
        return
    # get std input from state
    stdin_input = simgr.vuln[0].posix.dumps(0)

    # extract integers of length 10
    integer_inputs = []
    for i in range(0, len(stdin_input), 10):
        chunk = stdin_input[i:i+10]
        integer = bytes_to_int(chunk)
        integer_inputs.append(integer)

    # Convert the list of integers back to a byte string for stdin
    integer_stdin = '\n'.join(map(str, integer_inputs)).encode('utf-8') + b'\n'

    # Run the binary with the extracted stdin input
    TBLUE =  '\033[34m'
    TWHITE = '\033[37m'
    print(TBLUE + f"Run vulnerability for {binname}", TWHITE)
    try:
        result = subprocess.run(
            [f"./{binname}"],
            input=integer_stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Print the output and errors
        print(result.stdout.decode('utf-8', errors='ignore'), end="")
        if result.stderr:
            print(f"Binary errors:\n{result.stderr.decode('utf-8', errors='ignore')}")

    except Exception as e:
        print(f"Error running binary: {e}")

def create_binary(filename, binname):
    cmd = ["g++", filename, "-O0", "-o", binname]
    proc = subprocess.run(cmd)
    verbose(f"Ended building {binname}")
    return proc.returncode

def build(category, symb_or_conc, correct_or_incorrect, number):
    if not BUILD:
        return
    filename = get_filename(category, symb_or_conc, correct_or_incorrect, number)
    binname = get_binname(category, symb_or_conc, correct_or_incorrect, number)
    remove_file(binname)
    create_binary(filename, binname)

def run(category, symb_or_conc, correct_or_incorrect, number):
    binname = get_binname(category, symb_or_conc, correct_or_incorrect, number)
    modes = []
    if HMM:
        modes.append(shadow.ShadowMemory.m_HMM)
    if HMU_ord:
        modes.append(shadow.ShadowMemory.m_HMU_ord)
    if HMU_unord:
        modes.append(shadow.ShadowMemory.m_HMU_unord)
    found, simgr, proj = detector.detect(binname, modes, output=OUTPUT, verbose=VERBOSE, use_mem_access_concretization_for_shadow_check=CONCRETIZE)

    error = get_error_message(binname) # error message to display if the tests show that the detector has a bug
    check(found, simgr, proj, error, correct_or_incorrect) # check if the detector worked correctly

    # if detector finds a vulnerability, run the binary
    if found:
        run_vulnerability(simgr, binname)

    TGREEN =  '\033[32m'
    TWHITE = '\033[37m'
    print(TGREEN + f"{get_binname(category, symb_or_conc, correct_or_incorrect, number)} passed", TWHITE)

def build_and_run_selected_files(category=None, symb_or_conc=None, correct_or_incorrect=None, number=None):
        for spec_category in (["MemoryManagement", "MemoryUsage"] if category == None else [category]):
            for spec_symb_or_conc in (["Symbolic", "Concrete"] if symb_or_conc == None else [symb_or_conc]):
                for spec_correct_or_incorrect in (["Correct", "Incorrect"] if correct_or_incorrect == None else [correct_or_incorrect]):
                    num = 0
                    with open(f"tests/{spec_category}/{spec_symb_or_conc}/{spec_correct_or_incorrect}/number.txt", "r") as f:
                        num = int(f.read().strip())
                    if num >=1:
                        for spec_number in (range(1, num+1) if number == None else [number]):
                            spec_number = f"_{spec_number}"
                            build(spec_category, spec_symb_or_conc, spec_correct_or_incorrect, spec_number)
                            run(spec_category, spec_symb_or_conc, spec_correct_or_incorrect, spec_number)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-which",
                        type=str,
                        default="all",
                        help="To run all tests, provide argument 'all'." \
                        "To run a sub-set of the tests, provide the subfolder you want to run, e.g. 'MemoryManagement', or 'MemoryManagement/Concrete/Correct/1'"
                        )
    parser.add_argument("-HMM",
                        action="store_true",
                        help="Use the detector's ability to detect heap memory management vulnerabilities."
                        )
    parser.add_argument("-HMU_ord",
                        action="store_true",
                        help="Use the detector's ability to detect heap memory usage vulnerabilities, using an ordered data structure for the shadow memory."
                        )
    parser.add_argument("-HMU_unord",
                        action="store_true",
                        help="Use the detector's ability to detect heap memory usage vulnerabilities, using an unordered data structure for the shadow memory."
                        )
    parser.add_argument("-o",
                        action="store_true",
                        help="Enable some basic output."
                        )
    parser.add_argument("-v",
                        action="store_true",
                        help="Enable verbose output."
                        )
    parser.add_argument("-b",
                        action="store_true",
                        help="Build all test binaries which are to be tested again. If they are not built, you must provide this option.")
    parser.add_argument("-r",
                        action="store_true",
                        help="Run each testfile which contains a vulnerability after analysing it.")
    parser.add_argument("-c",
                        action="store_true",
                        help="Concretize shadow memory checks according to angr's default address concretization strategies.")
    args = parser.parse_args()

    if args.v:
        global VERBOSE
        VERBOSE = True
    if args.o:
        global OUTPUT
        OUTPUT = True
    if args.b:
        global BUILD
        BUILD = True
    if args.r:
        global RUN
        RUN = True
    if args.HMM:
        global HMM
        HMM = True
    if args.HMU_ord:
        global HMU_ord
        HMU_ord = True
    if args.HMU_unord:
        global HMU_unord
        HMU_unord = True
    if args.c:
        global CONCRETIZE
        CONCRETIZE = True

    which = args.which
    if which == "all":
        build_and_run_selected_files()
    else:
        path_elements = which.split("/")
        if len(path_elements) > 4:
            print("Wrong input")
            return
        category = path_elements[0]
        if os.path.exists(f"tests/{category}"):
            if len(path_elements) < 2:
                build_and_run_selected_files(category=category)
                return
            symb_or_conc = path_elements[1]
            if os.path.exists(f"tests/{category}/{symb_or_conc}"):
                if len(path_elements)<3:
                    build_and_run_selected_files(category=category, symb_or_conc=symb_or_conc)
                    return
                correct_or_incorrect = path_elements[2]
                if os.path.exists(f"tests/{category}/{symb_or_conc}/{correct_or_incorrect}"):
                    if len(path_elements)<4:
                        build_and_run_selected_files(category=category, symb_or_conc=symb_or_conc, correct_or_incorrect=correct_or_incorrect)
                        return
                    number = path_elements[3]
                    if os.path.exists(f"tests/{category}/{symb_or_conc}/{correct_or_incorrect}/_{number}"):
                        build_and_run_selected_files(category=category, symb_or_conc=symb_or_conc, correct_or_incorrect=correct_or_incorrect, number=number)
                    else:
                        print("Wrong input")
                        return
                else:
                    print("Wrong input")
                    return
            else:
                print("Wrong input")
                return
        else:
            print("Wrong input")
            return

if __name__ == "__main__":
    main()