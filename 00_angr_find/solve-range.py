import angr
import sys
import claripy
    
def main(argv):
  bin_path = argv[1]
  proj = angr.Project(bin_path)
  
  start_addr = 0x140001508 # Emu after __mingw_scanf
  init_state = proj.factory.blank_state(addr = start_addr,
    add_options = { angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS }
  )

  buf = init_state.regs.rbp - 0xD
  input_buf = claripy.BVS('input', 8*9)
  init_state.memory.store(buf, input_buf)

  simgr = proj.factory.simgr(init_state)

  target_addr = 0x140001565
  simgr.explore(find = target_addr)

  if simgr.found :
    solution_state = simgr.found[0]
    print(solution_state.solver.eval(input_buf, cast_to=bytes).decode())
  else :
    raise Exception("Path not found.")

if __name__ == '__main__':
  main(sys.argv)