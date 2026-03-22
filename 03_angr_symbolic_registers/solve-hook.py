import angr
import sys
import claripy

class InputHook(angr.SimProcedure):
  global input_a, input_b, input_d
  input_a = claripy.BVS('input_a', 32)
  input_b = claripy.BVS('input_b', 32)
  input_d = claripy.BVS('input_d', 32)
  def run(self):
    self.state.regs.eax = input_a
    self.state.regs.ebx = input_b
    self.state.regs.edx = input_d

def main(argv):
  bin_path = argv[1]
  proj = angr.Project(bin_path)

  start_addr = 0x140001707
  init_state = proj.factory.blank_state(addr = start_addr,
    add_options = { angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS }
  )

  proj.hook(0x1400016D5, InputHook())

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