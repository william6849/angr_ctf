import angr
import sys
import claripy

def main(argv):
  bin_path = argv[1]
  proj = angr.Project(bin_path)
  
  state = proj.factory.blank_state(addr = 0x14000165F)

  input_a = claripy.BVS('input_a', 32)
  input_b = claripy.BVS('input_b', 32)

  # x64 call stack doesn’t use stack-passed parameters. It uses registers instead.
  state.stack_push(state.regs.rbp)
  state.regs.rbp = state.regs.rsp
  state.regs.rsp -= 0x30

  # Angr using big-endian as default in low-level mem ops. Ref: https://docs.angr.io/en/latest/core-concepts/states.html
  state.memory.store(state.regs.rbp - 0x4, input_a, endness=proj.arch.memory_endness)
  state.memory.store(state.regs.rbp - 0x8, input_b, endness=proj.arch.memory_endness)

  simgr = proj.factory.simgr(state)

  simgr.explore(find = 0x14000169E)

  if simgr.found :
    print(simgr.found[0].solver.eval(input_a))
    print(simgr.found[0].solver.eval(input_b))
  else :
    raise Exception('Path not found') 

if __name__ == '__main__':
  main(sys.argv)