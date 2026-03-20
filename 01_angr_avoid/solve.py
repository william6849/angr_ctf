import angr
import sys
import claripy

class ScanfHook(angr.SimProcedure):
  global input_buf 
  input_buf = claripy.BVS('input', 8 * 20)
  def run(self, str_, buf_):
    rdx = self.state.regs.rdx
    self.state.memory.store(rdx, input_buf)

def main(argv):
  bin_path = argv[1]
  proj = angr.Project(bin_path)

  start_addr = 0x14000153E
  init_state = proj.factory.blank_state(addr = start_addr,
    add_options = { angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS }
  )

  proj.hook(0x140081D40, ScanfHook())

  simgr = proj.factory.simgr(init_state)

  target_addr = 0x140001516
  simgr.explore(find = target_addr, avoid=0x1400014D3)

  if simgr.found:
    print(simgr.found[0].solver.eval(input_buf, cast_to=bytes).decode())
  else:
    raise Exception("Path not found.")


if __name__ == '__main__':
  main(sys.argv)