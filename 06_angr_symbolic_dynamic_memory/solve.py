import angr
import sys
import claripy

def main(argv):
    bin = argv[1]
    proj = angr.Project(bin)
    
    init_state = proj.factory.blank_state(addr = 0x140001570)

    init_state.memory.store(0x1429B9518, 0x140F7D080, size=64, endness=proj.arch.memory_endness)
    init_state.memory.store(0x1429B9520, 0x140F7D089, size=64, endness=proj.arch.memory_endness)

    input_1 = claripy.BVS('input_1', 8 * 9)
    input_2 = claripy.BVS('input_2', 8 * 9)
    init_state.memory.store(0x140F7D080, input_1)
    init_state.memory.store(0x140F7D089, input_2)

    simgr = proj.factory.simgr(init_state)

    simgr.explore(find = 0x14000163B)

    if simgr.found:
        state = simgr.found[0]
        print(state.solver.eval(input_1, cast_to=bytes).decode())
        print(state.solver.eval(input_2, cast_to=bytes).decode())
    else:
        raise Exception('Path not found.')

if __name__ == '__main__':
    main(sys.argv)