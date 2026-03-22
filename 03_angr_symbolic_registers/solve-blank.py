import angr
import sys
import claripy

def main(argv):
  bin_path = argv[1]
  proj = angr.Project(bin_path)

  start_addr = 0x14000172c
  init_state = proj.factory.blank_state(addr = start_addr,
    add_options = { angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS }
  )
  input_a = claripy.BVS('input_a', 8 * 4)
  input_b = claripy.BVS('input_b', 8 * 4)
  input_d = claripy.BVS('input_d', 8 * 4)
  init_state.regs.eax = input_a
  init_state.regs.ebx = input_b
  init_state.regs.edx = input_d

  simgr = proj.factory.simgr(init_state)

  simgr.explore(find = 0x140001776)

  if simgr.found:
    print(hex(simgr.found[0].solver.eval(input_a)))
    print(hex(simgr.found[0].solver.eval(input_b)))
    print(hex(simgr.found[0].solver.eval(input_d)))
  else:
    raise Exception("Path not found.")

if __name__ == '__main__':
  main(sys.argv)