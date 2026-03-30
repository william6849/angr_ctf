import angr
import sys
import claripy

def target(state):
    return b'Good Job.' in state.posix.dumps(1)

def main(argv):
    bin = argv[1]
    proj = angr.Project(bin)
    
    init_state = proj.factory.blank_state(addr = 0x140001663,
        add_options = { angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS }
        )

    input_1 = claripy.BVS('input_1', 8 * 64)
    file_name = 'HNAJIIRX.txt'
    file_sim = angr.SimFile(file_name, input_1, 64)
    
    init_state.fs.insert(file_name, file_sim)

    simgr = proj.factory.simgr(init_state)

    simgr.explore(find = target)

    if simgr.found:
        state = simgr.found[0]
        print(state.solver.eval(input_1, cast_to=bytes))
    else:
        raise Exception('Path not found.')

if __name__ == '__main__':
    main(sys.argv)