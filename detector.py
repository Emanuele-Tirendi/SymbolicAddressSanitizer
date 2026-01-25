import angr
import monkeyhex
import shadow
import claripy
import math

VERBOSE = "verbose"
OUTPUT = "output"
ENABLED_MEM_INSTRUMENTATION = "enabled_mem_instrumentation"
CONCRETIZATION_REQUIRED = "concretization_required"
USE_MEM_ACCESS_CONCRETIZATION_FOR_SHADOW_CHECK = "use_mem_access_concretization_for_shadow_check"
DATA_FOR_CONCRETIZATION_BP = "data_for_concretization_bp"
VULN = "vuln"
VULN_MESSAGE = "vuln_message"
VULN_FOUND = "vuln_found"

def output_print(s, output):
    if output:
        print(f"O: {s}")

def verbose_print(s, verbose):
    if verbose:
        print(f"V: {s}")

def concretize_alloc_size(size, solver):
    if isinstance(size, int):
        return size
    elif not solver.symbolic(size):
        return solver.eval(size)
    else:
        return solver.max_int(size)

def handle_vulnerability(state, vuln_constraint, vuln_message):
    state.globals[VULN_MESSAGE] = vuln_message
    output_print(vuln_message, state.globals[OUTPUT])
    state.globals[VULN_FOUND] = True
    state.solver.add(vuln_constraint)

def move_to_vuln_stash(simgr):
    for stash in simgr.stashes:
        if stash != VULN:
            for state in simgr.stashes[stash]:
                if VULN_FOUND in state.globals.keys() and state.globals[VULN_FOUND]:
                    simgr.move(from_stash=stash, to_stash=VULN, filter_func=lambda s: s==state)

def check_memory_access(addr, condition, action, length, state):
    """
    Args:
        addr: the potentially symbolic address to check for in shadow memory
        condition: The constraint constraining addr to only take values according to
                   the concretization strategy that angr uses for memory access. If it
                   is desired that shadow access is not concretized, condition must be set
                   to True
        action: "r" for read, "w" for write
        length: length of the memory access. Cannot be symbolic.
        state: The angr state on which memory access takes place.
    """
    shadow = state.shadow
    
    symb_length = claripy.BVS("length", 32)
    length_condition = claripy.And(symb_length >= 0, symb_length < length)
    condition = claripy.And(condition, length_condition)

    if state.globals[shadow.m_HMU_ord]:
        # check, when shadow[addr+symb_length] is zero (poisoned area)
        when_zero_addr, when_zero_size = shadow.when_zero(shadow.m_HMU_ord, [addr+symb_length, condition], state.solver)
        # if there is at least one address where shadow[addr+symb_length] is zero
        if when_zero_addr!=None:
            vuln_condition = addr+symb_length==when_zero_addr
            # if shadow[addr+symb_length] is only zero when a buffer has a specific size
            if not when_zero_size == None:
                # add to the vulnerability condition that the size of the buffer when_zero_size[0] must be the size required to access poisoned area, i.e. when_zero_size[1]
                vuln_condition = claripy.And(vuln_condition, when_zero_size[0]==when_zero_size[1])
            handle_vulnerability(state, vuln_condition, f"VULNERABILITY recognised by {shadow.m_HMU_ord} at attempt to {action}-access memory at {hex(when_zero_addr)} {f'with buffer size {hex(when_zero_size[1])}' if when_zero_size is not None else ''}")
            return

    if state.globals[shadow.m_HMU_unord]:
        # check, when shadow[addr+symb_length] is zero (poisoned area)
        when_zero_addr, when_zero_size = shadow.when_zero(shadow.m_HMU_unord, [addr+symb_length, condition], state.solver)
        # if there is at least one address where shadow[addr+symb_length] is zero
        if when_zero_addr!=None:
            vuln_condition = addr+symb_length==when_zero_addr
            # if shadow[addr+symb_length] is only zero when a buffer has a specific size
            if not when_zero_size == None:
                # add to the vulnerability condition that the size of the buffer when_zero_size[0] must be the size required to access poisoned area, i.e. when_zero_size[1]
                vuln_condition = claripy.And(vuln_condition, when_zero_size[0]==when_zero_size[1])
            handle_vulnerability(state, vuln_condition, f"VULNERABILITY recognised by {shadow.m_HMU_unord} at attempt to {action}-access memory at {hex(when_zero_addr)} {f'with buffer size {hex(when_zero_size[1])}' if when_zero_size is not None else ''}")
            return

def instrumentation_before_address_concretization(state):
    if not state.globals[CONCRETIZATION_REQUIRED]:
        return
    # store which strategy is used
    state.globals[DATA_FOR_CONCRETIZATION_BP]["strategy"] = state.inspect.address_concretization_strategy

def instrumentation_after_address_concretization(state):
    if not state.globals[CONCRETIZATION_REQUIRED]:
        return

    addresses = state.inspect.address_concretization_result
    action = state.globals[DATA_FOR_CONCRETIZATION_BP]["action"]
    # if concretization didn't yield addresses, current concrtization strategy didn't work
    if addresses == None:
        strategy_no = state.globals[DATA_FOR_CONCRETIZATION_BP]["strategy_no"]
        strategies = state.memory.write_strategies if action == "w" else state.memory.read_strategies
        # if this was the last strategy, memory access won't take place and we don't have to check in shadow memory
        if len(strategies) <= strategy_no+1:
            state.globals[CONCRETIZATION_REQUIRED] = False
            return
        # else, increment the strategy number and wait for the next breakpoints before and after concretization
        else:
            state.globals[DATA_FOR_CONCRETIZATION_BP]["strategy_no"] = strategy_no + 1
            return
    
    # concretization did work

    state.globals[CONCRETIZATION_REQUIRED] = False

    strategy = state.globals[DATA_FOR_CONCRETIZATION_BP]["strategy"]
    addr = state.globals[DATA_FOR_CONCRETIZATION_BP]["addr"]
    length = state.globals[DATA_FOR_CONCRETIZATION_BP]["length"]
    # depending on concretization strategy, store in condition the constraint that must be true
    # such that the address is concretized according to the concretization strategy. This constraint
    # will be used by shadow memory.
    if isinstance(strategy, angr.concretization_strategies.range.SimConcretizationStrategyRange):
        sorted_addresses = sorted(addresses)
        min = sorted_addresses[0]
        max = sorted_addresses[-1]
        condition = claripy.And(addr>=min, addr<=max)
    elif isinstance(strategy, angr.concretization_strategies.max.SimConcretizationStrategyMax):
        condition = addr == addresses[0]
    elif isinstance(strategy, angr.concretization_strategies.any.SimConcretizationStrategyAny):
        condition = addr == addresses[0]
    else:
        condition = True

    check_memory_access(addr, condition, action, length, state)

def instrumentation_for_memory_access(action, state):
    if not state.globals[ENABLED_MEM_INSTRUMENTATION]:
        return

    # extract address and length of memory access
    if action == "r":
        addr = state.inspect.mem_read_address
        length = state.inspect.mem_read_length
    elif action == "w":
        addr = state.inspect.mem_write_address
        length = state.inspect.mem_write_length
        # state.memory.store does not require a length, so the length
        # needs to be extracted by the value being stored
        if length == None:
            value = state.inspect.mem_write_expr
            length = value.args[1]
            length = math.ceil(length / 8)
    else:
        raise Exception(f"Wrong action {action} for instrumentation_for_memory_access")

    heap_base = state.heap.heap_base
    heap_size = state.heap.heap_size

    # Check if address is in heap. If not, return since all current modes
    # operate on heap.
    if ((isinstance(addr, int) or not state.solver.symbolic(addr)) and
        (isinstance(length, int) or not state.solver.symbolic(length))):
        if not isinstance(addr, int):
            addr = state.solver.eval(addr)
        if not isinstance(length, int):
            length = state.solver.eval(length)
        satisfiable_any_addr_in_heap = addr+length>=heap_base and addr+length<heap_base+heap_size
    else:
        any_addr_in_heap = claripy.And(addr+length>=heap_base,addr+length<heap_base+heap_size)
        satisfiable_any_addr_in_heap = state.solver.satisfiable(extra_constraints=[any_addr_in_heap])
    if satisfiable_any_addr_in_heap:
        if state.globals[VERBOSE]:
            verbose_print(f"{'read' if action == 'r' else 'write'} at addr {hex(addr) if isinstance(addr, int) else addr} with max {hex(addr) if isinstance(addr, int) else hex(state.solver.max(addr))}, min {hex(addr) if isinstance(addr, int) else hex(state.solver.min(addr))} ,length: {hex(length) if isinstance(length, int) else length}", state.globals[VERBOSE])
    else:
        return

    # if address is symbolic, and USE_MEM_ACCESS_CONCRETIZATION_FOR_SHADOW_CHECK
    # equals true, then need to concretize shadow access. In that case, return
    # and wait for breakpoints at address concretization to continue.
    if isinstance(addr, int):
        condition = True
    else:
        if state.globals[USE_MEM_ACCESS_CONCRETIZATION_FOR_SHADOW_CHECK]:
            state.globals[CONCRETIZATION_REQUIRED] = True
            state.globals[DATA_FOR_CONCRETIZATION_BP] = {}
            state.globals[DATA_FOR_CONCRETIZATION_BP]["addr"] = addr
            state.globals[DATA_FOR_CONCRETIZATION_BP]["action"] = action
            state.globals[DATA_FOR_CONCRETIZATION_BP]["length"] = length
            state.globals[DATA_FOR_CONCRETIZATION_BP]["strategy_no"] = 0
            return
        else:
            condition = True

    check_memory_access(addr, condition, action, length, state)

# break point before memory writes
def instrumentation_before_mem_write(state):
    instrumentation_for_memory_access("w", state)

# break point before memory reads
def instrumentation_before_mem_read(state):
    instrumentation_for_memory_access("r", state)

class MallocInstrumentation(angr.SimProcedure):
    def run(self, size):

        # Perform malloc
        conc_size = concretize_alloc_size(size, self.state.solver)
        self.state.globals[ENABLED_MEM_INSTRUMENTATION] = False
        ptr = self.state.heap._malloc(conc_size)
        self.state.globals[ENABLED_MEM_INSTRUMENTATION] = True
        verbose_print(f"malloc with ptr: {hex(ptr)}, size: {hex(conc_size)}", self.state.globals[VERBOSE])

        shadow = self.state.shadow

        # Update shadow memory for mode shadow.m_HMM
        if self.state.globals[shadow.m_HMM]:
            if not ptr == None:
                shadow.set(shadow.m_HMM, ptr, True)

        # Update shadow memory for mode shadow.m_HMU_ord
        if self.state.globals[shadow.m_HMU_ord]:
            if not ptr == None:
                shadow.set(shadow.m_HMU_ord, [ptr, size], True, self.state.solver)

        # Update shadow memory for mode shadow.m_HMU_unord
        if self.state.globals[shadow.m_HMU_unord]:
            if not ptr == None:
                shadow.set(shadow.m_HMU_unord, [ptr, size], True, self.state.solver)
    
        return ptr
    
class CallocInstrumentation(angr.SimProcedure):
    def run(self, num, size):

        # Perform calloc
        conc_size = concretize_alloc_size(size, self.state.solver)
        conc_num = concretize_alloc_size(num, self.state.solver)
        self.state.globals[ENABLED_MEM_INSTRUMENTATION] = False
        ptr = self.state.heap._calloc(conc_num, conc_size)
        self.state.globals[ENABLED_MEM_INSTRUMENTATION] = True
        verbose_print(f"calloc with ptr: {hex(ptr)}, num: {hex(conc_num)}, size: {hex(conc_size)}", self.state.globals[VERBOSE])

        shadow = self.state.shadow

        # Update shadow memory for mode shadow.m_HMM
        if self.state.globals[shadow.m_HMM]:
            if not ptr == None:
                shadow.set(shadow.m_HMM, ptr, True)

        # Update shadow memory for mode shadow.m_HMU_ord
        if self.state.globals[shadow.m_HMU_ord]:
            if not ptr == None:
                shadow.set(shadow.m_HMU_ord, [ptr, num*size], True, self.state.solver)

        # Update shadow memory for mode shadow.m_HMU_unord
        if self.state.globals[shadow.m_HMU_unord]:
            if not ptr == None:
                shadow.set(shadow.m_HMU_unord, [ptr, num*size], True, self.state.solver)

        return ptr
    
class FreeInstrumentation(angr.SimProcedure):
    def run(self, ptr):

        shadow = self.state.shadow
        ptr_to_free = self.state.solver.max_int(ptr)

        # Check if free accesses poisoned area
        if self.state.globals[shadow.m_HMM]:
            if ptr_to_free != 0:
                when_zero = shadow.when_zero(shadow.m_HMM, ptr, self.state.solver)
                if not when_zero == None:
                    handle_vulnerability(self.state, ptr==when_zero, f"VULNERABILITY recognised by {shadow.m_HMM} at attempt to free at {hex(when_zero)}")
                    return

        # Perform free
        self.state.globals[ENABLED_MEM_INSTRUMENTATION] = False
        self.state.heap._free(ptr_to_free)
        self.state.globals[ENABLED_MEM_INSTRUMENTATION] = True
        verbose_print(f"free with ptr: {hex(ptr_to_free)}", self.state.globals[VERBOSE])
        
        # Update shadow memory for mode shadow.m_HMM
        if self.state.globals[shadow.m_HMM]:
            if ptr_to_free != 0:
                shadow.set(shadow.m_HMM, ptr_to_free, False)

        # Update shadow memory for mode shadow.m_HMU_ord
        if self.state.globals[shadow.m_HMU_ord]:
            if ptr_to_free != 0:
                shadow.set(shadow.m_HMU_ord, [ptr_to_free, None], False, self.state.solver) 

        # Update shadow memory for mode shadow.m_HMU_unord
        if self.state.globals[shadow.m_HMU_unord]:
            if ptr_to_free != 0:
                shadow.set(shadow.m_HMU_unord, [ptr_to_free, None], False, self.state.solver) 
    
class ReallocInstrumentation(angr.SimProcedure):
    def run(self, argptr, size):

        shadow = self.state.shadow
        ptr_to_realloc = self.state.solver.max_int(argptr)

        # Check if realloc accesses poisoned area
        if self.state.globals[shadow.m_HMM]:
            if ptr_to_realloc != 0:
                when_zero = shadow.when_zero(shadow.m_HMM, argptr, self.state.solver)
                if not when_zero == None:
                    handle_vulnerability(self.state, argptr==when_zero, f"VULNERABILITY recognised by {shadow.m_HMM} at attempt to realloc at {hex(when_zero)}")
                    return None

        # Perform realloc
        conc_size = concretize_alloc_size(size, self.state.solver)
        self.state.globals[ENABLED_MEM_INSTRUMENTATION] = False
        retptr = self.state.heap._realloc(ptr_to_realloc, conc_size)
        self.state.globals[ENABLED_MEM_INSTRUMENTATION] = True
        verbose_print(f"realloc with arg ptr: {hex(ptr_to_realloc)}, ret ptr: {hex(retptr)}, size: {hex(conc_size)}", self.state.globals[VERBOSE])

        # Update shadow memory for mode shadow.m_HMM
        if self.state.globals[shadow.m_HMM]:
            if ptr_to_realloc!=0 and conc_size!=0 and retptr!=None:
                # successful reallocation
                shadow.set(shadow.m_HMM, ptr_to_realloc, False)
                shadow.set(shadow.m_HMM, retptr, True)
            if ptr_to_realloc!=0 and conc_size==0:
                # successful free
                shadow.set(shadow.m_HMM, ptr_to_realloc, False)
            if ptr_to_realloc==0 and retptr!=None:
                # successful malloc
                shadow.set(shadow.m_HMM, retptr, True)

        # Update shadow memory for mode shadow.m_HMU_ord
        if self.state.globals[shadow.m_HMU_ord]:
            solver = self.state.solver
            if ptr_to_realloc!=0 and conc_size!=0 and retptr!=None:
                # successful reallocation
                shadow.set(shadow.m_HMU_ord, [ptr_to_realloc, None], False, solver)
                shadow.set(shadow.m_HMU_ord, [retptr, size], True, solver)
            if ptr_to_realloc!=0 and conc_size==0:
                # successful free
                shadow.set(shadow.m_HMU_ord, [ptr_to_realloc, None], False, solver)
            if ptr_to_realloc==0 and retptr!=None:
                # successful malloc
                shadow.set(shadow.m_HMU_ord, [retptr, size], True, solver)

        # Update shadow memory for mode shadow.m_HMU_unord
        if self.state.globals[shadow.m_HMU_unord]:
            solver = self.state.solver
            if ptr_to_realloc!=0 and conc_size!=0 and retptr!=None:
                # successful reallocation
                shadow.set(shadow.m_HMU_unord, [ptr_to_realloc, None], False, solver)
                shadow.set(shadow.m_HMU_unord, [retptr, size], True, solver)
            if ptr_to_realloc!=0 and conc_size==0:
                # successful free
                shadow.set(shadow.m_HMU_unord, [ptr_to_realloc, None], False, solver)
            if ptr_to_realloc==0 and retptr!=None:
                # successful malloc
                shadow.set(shadow.m_HMU_unord, [retptr, size], True, solver)

        return retptr

def detect(filename, modes, output=False, verbose=False,
           use_mem_access_concretization_for_shadow_check=False):
    """
    Detect vulnerabilities.

    Args:

        filename (string): The path to the binary to be analyzed.

        modes list(string): The list of modes to be used for analyzing. There are
        three modes that can be used:
        * shadow.ShadowMemory.m_HMM: check correct heap memory management
        * shadow.ShadowMemory.m_HMU_ord): check correct heap memory usage, using an
          ordered data structure (binary search tree) as shadow memory
        * shadow.ShadowMemory.m_HMU_unord): check correct heap memory usage, using an
          unordered data structure (set) as shadow memory

        output (bool): Provide basic output.

        verbose (bool): Provide verbose output. Verbose output outputs heap management
        or memory accesses with the corresponding pointers and addresses. It prints the (potentially)
        symbolic address as well as concretizations of it to show an example. Note here that
        these concretizations must not be the same ones that appear when someone tries to evaluate
        these expressions at a later point with solver.state.eval(addr) or - if addresses depended
        on user input - with state.posix.dumps(0).

        use_mem_access_concretization_for_shadow_check (bool): When m_HMU_ord or m_HMU_unord
        are enabled, on every memory access within the heap, the shadow memory checks whether
        this access is located in a poisoned area. The argument use_mem_access_concretization_for_shadow_check
        configuees whether the shadow memory should use the same concretization strategies for
        shadow memory access as angr does for regular memory access.

    Returns:
        
        found (bool): A flag indicating whether a vulnerability has been found.

        simgr (SimulationManager): The simulation manager after the detection of the vulnerable states.
        In the stash simgr.vuln there are all states for which a vulnerability was found. Let state be
        a state in simgr.vuln, then state.globals[VULN_MESSAGE] is the message describing the
        vulnerability.
        
        proj (Project): The angr project used to detect the vulnerability.
    """

    # create angr project
    proj = angr.Project(filename, auto_load_libs=False)

    # find entry point
    cfg = proj.analyses.CFGFast()
    mainfunc = cfg.kb.functions.function(name="_main")

    # create state
    state = proj.factory.entry_state(addr=mainfunc.addr,
                                     add_options={angr.options.SYMBOLIC_WRITE_ADDRESSES,
                                                  angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                  angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
    
    # register heap plugin
    state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc())
    
    # register shadow memory
    state.register_plugin('shadow', shadow.ShadowMemory())
    heap_base = state.heap.heap_base
    heap_size = state.heap.heap_size

    # register modes that shadow memory should use
    info = {state.shadow.heap_base: heap_base, state.shadow.heap_size: heap_size}
    if state.shadow.m_HMM in modes:
        state.globals[state.shadow.m_HMM] = True
        state.shadow.register_mode(state.shadow.m_HMM, info=info)
    else:
        state.globals[state.shadow.m_HMM] = False
    if state.shadow.m_HMU_ord in modes:
        state.globals[state.shadow.m_HMU_ord] = True
        state.shadow.register_mode(state.shadow.m_HMU_ord, info=info)
    else:
        state.globals[state.shadow.m_HMU_ord] = False
    if state.shadow.m_HMU_unord in modes:
        state.globals[state.shadow.m_HMU_unord] = True
        state.shadow.register_mode(state.shadow.m_HMU_unord, info=info)
    else:
        state.globals[state.shadow.m_HMU_unord] = False
    
    # configure shadow memory access concretization
    state.globals[USE_MEM_ACCESS_CONCRETIZATION_FOR_SHADOW_CHECK] = use_mem_access_concretization_for_shadow_check

    # configure output
    state.globals[VERBOSE] = verbose
    if verbose:
        output = True
    state.globals[OUTPUT] = output

    # hooking and breakpoints used for shadow memory
    proj.hook_symbol("_malloc", MallocInstrumentation())
    proj.hook_symbol("_free",   FreeInstrumentation())
    proj.hook_symbol("_calloc", CallocInstrumentation())
    proj.hook_symbol("_realloc", ReallocInstrumentation())
    if state.globals[state.shadow.m_HMU_unord] or state.globals[state.shadow.m_HMU_ord]:
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=instrumentation_before_mem_write)
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=instrumentation_before_mem_read)
        if state.globals[USE_MEM_ACCESS_CONCRETIZATION_FOR_SHADOW_CHECK]:
            state.inspect.b('address_concretization', when=angr.BP_AFTER, action=instrumentation_after_address_concretization)
            state.inspect.b('address_concretization', when=angr.BP_BEFORE, action=instrumentation_before_address_concretization)

    # ENABLED_MEM_INSTRUMENTATION is dynamically set to False if malloc, free, calloc, realloc are
    # called in order to not let the memory instrumentation recognize those functions as
    # wrongful memory accesses
    state.globals[ENABLED_MEM_INSTRUMENTATION] = True
    # If a memory access is symbolic, and use_mem_access_concretization_for_shadow_check is
    # True, then CONCRETIZATION_REQUIRED is dynamically set to True to trigger the instrumentations before and
    # after address concretization.
    state.globals[CONCRETIZATION_REQUIRED] = False

    # create simulation manager
    simgr = proj.factory.simgr(state)
    # create stash in which vulnerable states are stored
    simgr.stashes[VULN] = []
    # run detection
    simgr.step()
    while (len(simgr.active) > 0):
        simgr.step()
        # after each step, move vulnerable states to the vuln stash
        move_to_vuln_stash(simgr)

    # check whether there are states that are not deadended or vulnerable
    if len(simgr.pruned) > 0:
        output_print(f"There are {len(simgr.pruned)} pruned states.",output)
    if len(simgr.unconstrained) > 0:
        output_print(f"There are {len(simgr.unconstrained)} unconstrained states.", output)
    if len(simgr.errored) > 0:
        output_print(f"There are {len(simgr.errored)} errored states.", output)
    if len(simgr.unsat) > 0:
        output_print(f"There are {len(simgr.unsat)} unsat states.", output)

    # return results
    vuln_found = True if len(simgr.vuln)>0 else False
    if vuln_found:
        output_print("Vulnerability found.", output)
        return True, simgr, proj
    else:
        output_print("No vulnerability found.", output)
        return False, simgr, proj