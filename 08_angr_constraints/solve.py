import angr
import sys
import claripy

def main(argv):
    bin = argv[1]
    proj = angr.Project(bin)
    
    init_state = proj.factory.blank_state(addr = 0x1400015AC)

    input = claripy.BVS('input', 8 * 17)
    
    init_state.memory.store(0x140015040, input)

    simgr = proj.factory.simgr(init_state)

    simgr.explore(find = 0x140001600)

    if simgr.found:
        state = simgr.found[0]
        buf = state.memory.load(0x140015040, 16)
        target = claripy.BVV(b"XFQUUEQFKBECVEJF")
        state.add_constraints(buf == target)
        print(state.solver.eval(input, cast_to=bytes).decode())
    else:
        raise Exception('Path not found.')

if __name__ == '__main__':
    main(sys.argv)