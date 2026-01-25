from sortedcontainers import SortedList
import copy
import angr
import claripy

class Node():
    def __init__(self, key, value, next=None):
        self.key = key
        self.value = value
        self.next = next
    
    def __repr__(self):
        return f"({self.key}, {self.value}, {self.next})"

class SortedDictWithSuccessor():
    """
    As inspired by the sorted dictionary from sortedcontainers, this is an
    implementation of a sorted dictionary which uses a sorted list and a
    python dictionary. The sorted list contains the sorted keys, while the
    dictionary contains the key-value-mapping.

    Each value v consists of a node object which has a reference to key predecessing
    the key of v in the sorted list.

    So, this data structure is asymptotically as fast with every operation
    as a binary search tree where each leaf has a reference to the next leaf.
    """
    def __init__(self):
        self.sl = SortedList() # stores the keys
        self.d = {} # stores the key-value mapping

    def set(self, key, value):
        """
        Insert a key-value pair in the SortedDictWithSuccessor
        """
        if key in self.d:
            # if key in dictionary, just update value
            self.d[key].value = value
        elif len(self.sl) == 0:
            # if there is no key-value pair, create one
            self.sl.add(key)
            node = Node(key, value)
            self.d[key] = node
        else:
            # get the index of the biggest key which is smaller than `key`
            bis_left = self.sl.bisect_left(key)
            if bis_left == 0:
                # if there is none, insert key-value at beginning of list
                rightkey = self.sl[bis_left]
                node = Node(key, value, rightkey)
                self.d[key] = node
            elif bis_left == len(self.sl):
                # if it is the last one, insert key-value at end of list
                leftkey = self.sl[bis_left-1]
                leftnode = self.d[leftkey]
                node = Node(key, value)
                self.d[key] = node
                leftnode.next = key
            else:
                # insert key-value within list
                leftkey = self.sl[bis_left-1]
                leftnode = self.d[leftkey]
                rightkey = self.d[leftkey].next
                node = Node(key, value, rightkey)
                self.d[key] = node
                leftnode.next = key
            self.sl.add(key)

    def remove(self, key):
        """
        Remove a key and the corresponding value from the SortedDictWithSuccessor.
        """
        if key not in self.d:
            # if key not in dictionary, remove
            return
        elif len(self.sl) == 1:
            # if key is the only one existing, delete it
            del self.d[key]
            self.sl.discard(key)
        else:
            bis_left = self.sl.bisect_left(key)
            # do case distinction
            if bis_left == 0:
                # case where key is the smallest one
                ...
            elif bis_left == len(self.sl):
                # case where key is the biggest one
                leftkey = self.sl[bis_left-1]
                self.d[leftkey].next = None
            else:
                # case where key lies between other two keys
                leftkey = self.sl[bis_left-1]
                leftnode = self.d[leftkey]
                rightkey = self.d[key].next
                leftnode.next = rightkey
            del self.d[key]
            self.sl.discard(key)

    def get_leq_key(self, key):
        """
        Get the key, value and predecessing key within the
        SortedDictWithSuccessor which is smaller or equal to `key`.
        """
        if key in self.d:
            # if key exists, return it
            return key, self.d[key].value, self.d[key].next
        elif len(self.sl) == 0:
            # if no key exists, return None
            return None, None, None
        else:
            bis_left = self.sl.bisect_left(key)
            if bis_left == 0:
                # if there is no smaller key, return None
                return None, None, None
            else:
                # return the smaller key
                leftkey = self.sl[bis_left-1]
                return leftkey, self.d[leftkey].value, self.d[leftkey].next
        
    def get_geq_key(self, key):
        """
        Get the key, value and predecessing key within the
        SortedDictWithSuccessor which is greater or equal to `key`.
        """
        if key in self.d:
            # if key exists, return it
            return key, self.d[key].value, self.d[key].next
        elif len(self.sl) == 0:
            # if no key exists, return None
            return None, None, None
        else:
            bis_right = self.sl.bisect_right(key)
            if bis_right == len(self.sl):
                # if there is no bigger key, return None
                return None, None, None
            else:
                # return bigger key
                rightkey = self.sl[bis_right]
                return rightkey, self.d[rightkey].value, self.d[rightkey].next
    
    def get(self, key):
        """
        Get the value of `key` and `key`'s predecessing key.
        """
        node = self.d[key]
        return node.value, node.next

    def __repr__(self):
        return self.d.__repr__()
    
class ShadowMemory(angr.SimStatePlugin):
    """
    This is an angr plugin implementing a shadow memory for detecting
    bugs and vulnerabilities.

    Currently, two types of vulnerability detection are supported, where for
    one type there are two different implementations which differ in the
    runtime behaviour. Each of these three implementations has a corresponding
    mode.

    m_HMM: Detects attempts to free or realloc a wrong pointer. The shadow memory defines
           each address which is the base of an allocated buffer to be unpoisonous. I.e. for each
           memory allocation at pointer p, user should do shadow[p] = 1. For each deallocation
           at pointer p, user should do shadow[p] = 0.
    m_HMU_ord: Detects attempts to access unallocated heap memory. Uses an ordered
               collection as data structure for shadow memory implementation. The shadow memory defines
               each address which is located within a buffer to be unpoisonous. I.e. for each
               memory allocation from address p to p+s, user should do shadow[p:p+s] = 1. For each deallocation
               at p+s, user should do shadow[p:p+s] = 0.
    m_HMU_unord: Detects attempts to access unallocated heap memory. Uses an unordered
                 collection as data structure for shadow memory implementation. The shadow memory defines
               each address which is located within a buffer to be unpoisonous. I.e. for each
               memory allocation from address p to p+s, user should do shadow[p:p+s] = 1. For each deallocation
               at p+s, user should do shadow[p:p+s] = 0.

    Instead of using shadow[x] = y, one should use the set function defined in this plugin.
    """

    # modes
    m_HMM = "m_HMM" # heap memory management
    m_HMU_ord = "m_HMU_ord" # heap memory usage, using an ordered collection as data structure
    m_HMU_unord = "m_HMU_unord" # heap memory usage, using an unordered collection as data structure
    modes = [m_HMM, m_HMU_ord, m_HMU_unord]

    heap_base = "heap_base"
    heap_size = "heap_size"

    _ptr_and_size = "_ptr_and_size"
    _single_addrs = "_single_addrs"
    _heap = "heap"
    _ptr = "ptr"
        
    def __init__(self):
        super(ShadowMemory, self).__init__()

        # store flags indicating which mode is used
        self._modes_in_use = {}
        for mode in self.modes:
            self._modes_in_use[mode] = False

        # Store all kinds of data structures that will be used. For any
        # mode m we will store the corresponding data structures in
        # self._data_str[m]
        self._data_str = {}

    def register_mode(self, mode, data_str=None, info=None):
        """
        This function registers the different modes that are used.
        
        All modes that the user wants to use must be registered with this function
        before any other function of this plugin is used.

        Args:
            mode: any mode in self.modes
            data_str: any data structure that the user wants to use for this mode.
                      This is used for copying the plugin and is not meant for use
                      by the user.

                      If None, for each currently supported mode, the wholeshadow memory
                      is initialized as poisonous.
            info: For any mode currently supported this must be provided. It must be
                  a dictionary of the form {shadow.heap_base: <heap_base>, shadow.heap_size: <heap_size>}

        """
        if mode not in self.modes:
            raise Exception(self.wrong_mode("register_mode", mode))      
        self._modes_in_use[mode] = True
        if data_str != None:
            self._data_str[mode] = data_str
        else:
            # initialize data structures
            if mode == self.m_HMM:
                self._data_str[self.m_HMM] = {self._ptr:set(),
                                             self.heap_base:info[self.heap_base],
                                             self.heap_size:info[self.heap_size],
                                             }
            if mode == self.m_HMU_unord:
                self._data_str[self.m_HMU_unord] = {self._ptr_and_size:{},
                                                   self._single_addrs:{},
                                                   self.heap_base:info[self.heap_base],
                                                   self.heap_size:info[self.heap_size]
                                                   }
            if mode == self.m_HMU_ord:
                self._data_str[self.m_HMU_ord] = {self._heap: SortedDictWithSuccessor(),
                                                 self.heap_base:info[self.heap_base],
                                                 self.heap_size:info[self.heap_size]
                                                 }

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        sm = ShadowMemory()
        for mode in self.modes:
            if self._modes_in_use[mode]:
                data_str_copy = copy.deepcopy(self._data_str[mode])
                sm.register_mode(mode, data_str_copy)
        return sm
    
    def wrong_mode(self, call, mode):
        return f"ShadowMemory: attempt to call '{call}' with invalid mode {mode}."

    def set(self, mode, addr, val:bool, solver=None):
        """
        This function writes into the shadow memory. If val == True, then it writes at addr
        the value 1 (unpoisoned), else it writes 0 (poisoned).

        Args:
            mode: Any mode of self.modes
            addr: This value differs depending on the modes.
                m_HMM: addr has type integer and is the base address of an allocated buffer.
                m_HMU_ord and m_HMU_unord:
                    if val == True: addr is a list of two values where first must be an integer and second can be
                    integer, claripy.BVV or claripy.BVS. addr[0] must represent the base address of
                    an allocated buffer while addr[1] must represent the size of the allocated buffer.
                    if val == False: addr[0] is the same while addr[1] should be None
            val: is a boolean which decides whether addr must become poisonous or not.
            solver: The angr solver of the state. Is currently only needed for m_HMU_ord and m_HMU_unord.

        Important: As of now the implementation assumes that the developer doesn't attempt to unpoison an address or
        buffer twice before poisoning it again. So attempting to unpoison an address twice will lead to errors.
        """
        if mode not in self.modes or not self._modes_in_use[mode]:
            raise Exception(self.wrong_mode("set", mode))
        if mode == self.m_HMM:
            self.set_for_m_HMM(addr, val, mode)
        if mode == self.m_HMU_ord:
            self.set_for_m_HMU_ord(addr, val, mode, solver)
        if mode == self.m_HMU_unord:
            self.set_for_m_HMU_unord(addr, val, mode, solver)

    def when_zero(self, mode, addr, solver):
        """
        This function checks whether the address `addr` is a poisonous address. If it is, it returns
        data which indicate at which condition `addr` is poisonous.

        Args:
            mode: Any mode of self.modes
            addr: This value differs depending on the modes.
                m_HMM: can be an integer, claripy.BVV or claripy.BVS
                m_HMU_ord and m_HMU_unord: addr is a list of two values. addr[0] can be an
                integer, claripy.BVV or claripy.BVS and represents an address. addr[1] is a
                concretization condition which constrains addr[0]. This can be used if it is
                desired that shadow memory access is concretized according to concretization
                strategies. If it is not desired, addr[1] must be just True.
            solver: The angr solver of the state. Is currently needed for all modes.

        Returns: Depends on the mode:
            m_HMM: It returns an integer representing the address to which `addr` needs to
            be concretized to (if it is symbolic) or `addr` itself, when access to this concretization
            or to `addr` would be an access to a poisoned area. If no access to poisoned area is possible,
            None is returned.
            m_HMU_ord and m_HMU_unord: It returns a list of two values, here called return.first and return.second. return.first is analogous
            to the value returned by m_HMM. If return.first is None, return.second is None as well. If return.first
            is not None, then return.second represents the following:
                If there is no model of the solver in which the return.first is located within a buffer, the return.second is None.
                If there is a model in which the return.first is within a buffer, return.second consists of a list
                of two values, here called return.second.first and return.second.second. return.second.first is the size of the buffer
                and return.second.second is the concretization of return.second.first which would be needed to make access to return.first
                be outside of the allocated buffer.

        """
        if mode not in self.modes or not self._modes_in_use[mode]:
            raise Exception(self.wrong_mode("when_zero", mode))
        if mode == self.m_HMM:
            return self.when_zero_for_m_HMM(addr, solver, mode)
        if mode == self.m_HMU_ord:
            return self.when_zero_for_m_HMU_ord(addr, solver, mode)
        if mode == self.m_HMU_unord:
            return self.when_zero_for_m_HMU_unord(addr, solver, mode)
        
    def set_for_m_HMM(self, addr, val:bool, mode):
        if mode != self.m_HMM:
            raise Exception(self.wrong_mode("set_for_m_HMM", mode))
        if not isinstance(addr, int):
            raise TypeError(f"Attempt to call 'set' on the shadow memory with mode {mode} with address of invalid type {type(addr)}. Type must be integer.")
        
        heap_base = self._data_str[mode][self.heap_base]
        heap_size = self._data_str[mode][self.heap_size]
        if not self.is_in_heap(addr, heap_base, heap_size):
            # if address not in heap, raise exception since this means that
            # there was a heap management function (like malloc) that returned
            # a pointer pointing outside of the heap, or another function (like free)
            # that attempted to free a pointer outside of the memory.
            raise Exception(f"Attempt to call 'set' {val} on the shadow memory with mode {mode} with address {addr} which is outside of the heap boundaries with heap_base: {heap_base}, heap_size: {heap_size}")
        
        data_str = self._data_str[mode][self._ptr]

        if val:
            # if val then set to 1
            data_str.add(addr)
        else:
            # if not val, and if set to 1 then set to 0
            if addr in data_str:
                data_str.remove(addr)

    def set_for_m_HMU_ord(self, addr, val:bool, mode, solver):
        if mode != self.m_HMU_ord:
            raise Exception(self.wrong_mode("set_for_m_HMU_ord", mode))
        if not isinstance(addr[0], int):
            raise TypeError(f"Attempt to call 'set' on the shadow memory with mode {mode} with address[0] of invalid type {type(addr)}. Type must be integer.")
        
        heap_base = self._data_str[mode][self.heap_base]
        heap_size = self._data_str[mode][self.heap_size]

        if val:
            is_in_heap = self.is_in_heap(addr[0]+addr[1], heap_base, heap_size)
        else:
            is_in_heap = self.is_in_heap(addr[0], heap_base, heap_size)
        if not (is_in_heap if isinstance(is_in_heap, bool) else solver.satisfiable(extra_constraints=[is_in_heap])):
            # setting any address outside of the heap to 1 or 0 means that any heap
            # management function operated without the heap which is not possible
            raise Exception(f"Attempt to call 'set' on the shadow memory with mode {mode} with address {addr[0]} and size {addr[1]} which is outside of the heap boundaries with heap_base: {heap_base}, heap_size: {heap_size}")

        data_str = self._data_str[mode][self._heap]

        if val:
            # store the address addr[0] and the size of the buffer addr[1]
            data_str.set(addr[0], addr[1])
        else:
            data_str.remove(addr[0])

    def set_for_m_HMU_unord(self, addr, val:bool, mode, solver):
        if mode != self.m_HMU_unord:
            raise Exception(self.wrong_mode("set_for_m_HMU_unord", mode))
        buffer_begin = addr[0]
        buffer_size = addr[1]

        if not isinstance(buffer_begin, int):
            raise TypeError(f"Attempt to call 'set' on the shadow memory with mode {self.m_HMU_unord} with buffer_begin of invalid type {type(addr)}. Type must be integer.")
        
        heap_base = self._data_str[mode][self.heap_base]
        heap_size = self._data_str[mode][self.heap_size]
        if val:
            is_in_heap = self.is_in_heap(addr[0]+addr[1], heap_base, heap_size)
        else:
            is_in_heap = self.is_in_heap(addr[0], heap_base, heap_size)
        if not (is_in_heap if isinstance(is_in_heap, bool) else solver.satisfiable(extra_constraints=[is_in_heap])):
            # setting any address outside of the heap to 1 or 0 means that any heap
            # management function operated without the heap which is not possible
            raise Exception(f"Attempt to call 'set' on the shadow memory with mode {mode} with address {addr[0]} and size {addr[1]} which is outside of the heap boundaries with heap_base: {heap_base}, heap_size: {heap_size}")
        
        ptr_and_size = self._data_str[mode][self._ptr_and_size]
        single_addrs = self._data_str[mode][self._single_addrs]

        if val:
            max_buffer_size = solver.max(buffer_size)
            
            # store for buffer_begin what it's size is
            ptr_and_size[buffer_begin] = (buffer_size, max_buffer_size)

            # store region from buffer_begin to buffer_begin+buffer_size as unpoisoned
            # and store for each one the buffer begin and buffer size
            for a in range(buffer_begin, buffer_begin + max_buffer_size):
                single_addrs[a] = buffer_begin
        else:
            # store region from buffer_begin to buffer_begin+buffer_size as poisoned
            size, max_buffer_size = ptr_and_size[buffer_begin]
            for a in range(buffer_begin, buffer_begin + max_buffer_size):
                del single_addrs[a]

            # remove stored buffer_size for buffer_begin
            del ptr_and_size[buffer_begin]

    def when_zero_for_m_HMM(self, addr, solver, mode):
        if mode != self.m_HMM:
            raise Exception(self.wrong_mode("when_zero_for_m_HMM", mode))
        data_str = self._data_str[mode][self._ptr]
        heap_base = self._data_str[mode][self.heap_base]
        heap_size = self._data_str[mode][self.heap_size]

        # if address not symbolic
        if isinstance(addr, int) or not solver.symbolic(addr):
            if not isinstance(addr, int):
                addr = solver.eval(addr)
            if not addr in data_str:
                # if shadow[addr] == 0 then we found a vulnerability
                return addr
            else:
                # no vulnerability here
                return None

        addr_in_heap = self.is_in_heap(addr, heap_base, heap_size)
        if not solver.satisfiable(extra_constraints=[addr_in_heap]):
            # if address cannot be in heap, each concretization of addr is access to poisoned area
            return solver.max(addr)
        
        minaddr = solver.min(addr, extra_constraints=[addr_in_heap])
        maxaddr = solver.max(addr, extra_constraints=[addr_in_heap])
        current = maxaddr
        # iterate over each concretization
        while current>=minaddr:
            # check for each concretization if it is poisonous
            if not current in data_str:
                # found poisonous
                return current
            if current>minaddr:
                current = solver.max(addr, extra_constraints=[addr<current, addr_in_heap])
            else:
                break
        # found nothing poisonous
        return None
    
    def when_zero_for_m_HMU_ord(self, addr, solver, mode):

        if mode != self.m_HMU_ord:
            raise Exception(self.wrong_mode("when_zero_for_m_HMU_ord", mode))
        data_str = self._data_str[mode][self._heap]
        heap_base = self._data_str[mode][self.heap_base]
        heap_size = self._data_str[mode][self.heap_size]

        addr_condition = addr[1]
        addr = addr[0]

        # if address is not symbolic
        if isinstance(addr, int) or not solver.symbolic(addr):
            if not isinstance(addr, int):
                addr = solver.eval(addr) 
            if not self.is_in_heap(addr, heap_base, heap_size):
                # if address not in heap, no vulnerability
                return None, None
            # store in leftaddr the buffer base of the buffer whose base is the biggest one being smaller than addr
            # store in leftsize the size of the buffer at leftaddr
            # store in rightaddr the buffer base of the next buffer
            leftaddr, leftsize, rightaddr = data_str.get_leq_key(addr)
            if leftaddr == None:
                # if there is no buffer whose base address <= addr, then addr does access poisoned area
                return addr, None
            if solver.satisfiable(extra_constraints=[addr > leftaddr+leftsize]):
                # if there is a model where addr is outside of the buffer defined by leftaddr, we found a vulnerabiliry
                concsize = solver.eval(leftsize, extra_constraints=[addr > leftaddr+leftsize])
                maxleftsize = solver.max(leftsize)
                if addr > leftaddr+maxleftsize:
                    # if addr is outside of buffer for any model, don't specify required size for making it outside
                    return addr, None
                else:
                    # if addr is outside of buffer just in case where leftsize==concsize, then return them as well together with addr
                    return addr, [leftsize, concsize]
                
            return None, None
            
        else:
            # if addr is symbolic
            addr_in_heap = self.is_in_heap(addr, heap_base, heap_size)
            if not solver.satisfiable(extra_constraints=[addr_in_heap, addr_condition]):
                # if access outside of heap, no vulnerability found
                return None, None
            minaddr = solver.min(addr, extra_constraints=[addr_in_heap, addr_condition])
            maxaddr = solver.max(addr, extra_constraints=[addr_in_heap, addr_condition])

            # store in leftaddr the buffer base of the buffer whose base is the biggest one being smaller than addr
            # store in leftsize the size of the buffer at leftaddr
            # store in rightaddr the buffer base of the next buffer
            leftaddr, leftsize, rightaddr = data_str.get_leq_key(minaddr)
            if leftaddr == None:
                # if there is no buffer whose base address <= addr, then addr does access poisoned area
                return minaddr, None
                
            # iterate over each buffer defined by leftaddr and check if there is amodel where addr is outside of it because addr is bigger
            while solver.satisfiable(extra_constraints=[addr > leftaddr+leftsize, addr_in_heap, addr_condition]):
                if rightaddr != None:
                    # if there is a buffer whose base address is bigger than leftaddr
                    # store in addr_between_buffers the condition needed for the model in which
                    # addr lies between the left buffer and the right buffer
                    addr_between_buffers = claripy.And(addr >= leftaddr+leftsize, addr < rightaddr)
                else:
                    # if there is no buffer on the right side, maxaddr accesses poisoned area for sure
                    return maxaddr, None

                if solver.satisfiable(extra_constraints=[addr_between_buffers, addr_in_heap, addr_condition]):
                    # if there is indeed a model where addr lies between left buffer and right buffer
                    [conc_addr, conc_size] = self.eval_pair(addr, leftsize, solver, [addr_between_buffers, addr_in_heap, addr_condition])
                    return conc_addr, [leftsize, conc_size]

                leftaddr = rightaddr
                leftsize, rightaddr = data_str.get(leftaddr)
                
            return None, None

    def when_zero_for_m_HMU_unord(self, addr, solver, mode):
        if mode != self.m_HMU_unord:
            raise Exception(self.wrong_mode("when_zero_for_m_HMU_unord", mode))
        single_addrs = self._data_str[mode][self._single_addrs]
        ptrs_and_sizes = self._data_str[mode][self._ptr_and_size]

        addr_condition = addr[1]
        addr = addr[0]

        if isinstance(addr, int) or not solver.symbolic(addr):
            if not isinstance(addr, int):
                addr = solver.eval(addr)
            if not self.is_in_heap(addr, heap_base, heap_size):
                # if access is outside of heap, we cannot detect vulnerability
                return None, None
            if addr in single_addrs:
                # if there is a model where addr is unpoisoned but there still might be models where it is poisoned
                base_addr = single_addrs[addr]
                size, max_size = ptrs_and_sizes[base_addr]
                # store in out_of_bounds the condition for the models where addr is poisoned
                out_of_bounds = claripy.And(addr>base_addr+size)
                if solver.satisfiable(extra_constraints=[out_of_bounds]):
                    # if there is a model where addr is poisoned, extract the concrete size needed for this
                    conc_size = solver.eval(size, extra_constraints=[out_of_bounds])
                    return addr, [size, conc_size]
                else:
                    # if there is no model where addr is poisoned, return None
                    return None, None
            else:
                # if there is no model where addr is unpoisoned
                return addr, None

        else:
            heap_base = self._data_str[mode][self.heap_base]
            heap_size = self._data_str[mode][self.heap_size]
            addr_in_heap = self.is_in_heap(addr, heap_base, heap_size)
            if not solver.satisfiable(extra_constraints=[addr_in_heap, addr_condition]):
                # if access is outside of heap, we cannot detect vulnerability
                return None, None
            
            minaddr = solver.min(addr, extra_constraints=[addr_in_heap, addr_condition])
            maxaddr = solver.max(addr, extra_constraints=[addr_in_heap, addr_condition])
            current = maxaddr
            # iterate over each concretization of addr
            while current>=minaddr:
                if current in single_addrs:
                    # if there is a model where addr is unpoisoned
                    base_addr = single_addrs[current]
                    size, max_size = ptrs_and_sizes[base_addr]
                    # store in out_of_bounds the condition for the models where addr is poisoned
                    # use for the maximum of the size the solver since max_size might not be the current max size anymore
                    out_of_bounds = claripy.And(current>base_addr+size, addr==current)
                    if solver.satisfiable(extra_constraints=[out_of_bounds, addr_in_heap, addr_condition]):
                        # if there is indeed a model where addr is poisoned
                        conc_size = solver.eval(size, extra_constraints=[out_of_bounds, addr_in_heap, addr_condition])
                        return current, [size, conc_size]
                else:
                    # if there is no model where addr is unpoisoned
                    return current, None
                
                if current>minaddr:
                    current = solver.max(addr, extra_constraints=[addr<current, addr_in_heap, addr_condition])
                else:
                    break
            return None, None
    
    def is_in_heap(self, addr, heap_base, heap_size):
        if not (isinstance(addr, int) and isinstance(heap_base, int) and isinstance(heap_size, int)):
            return claripy.And(heap_base<=addr, heap_base+heap_size>addr)
        else:
            return heap_base<=addr and heap_base+heap_size>addr
        
    def eval_pair(self, val1, val2, solver, extra_constraints):
        eval1 = solver.eval(val1, extra_constraints=extra_constraints)
        extra_constraints.append(val1==eval1)
        eval2 = solver.eval(val2, extra_constraints=extra_constraints)
        return eval1, eval2