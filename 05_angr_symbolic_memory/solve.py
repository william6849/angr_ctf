import angr
import sys
import claripy

def main(argv):
  bin_path = argv[1]
  proj = angr.Project(bin_path)
  
  state = proj.factory.blank_state(addr = 0x140001540)

  input_a = claripy.BVS('input_a', 8 * 8)
  input_b = claripy.BVS('input_b', 8 * 8)
  input_c = claripy.BVS('input_c', 8 * 8)
  input_d = claripy.BVS('input_d', 8 * 8)

  state.memory.store(0x1402BD880, input_a)
  state.memory.store(0x1402BD888, input_b)
  state.memory.store(0x1402BD890, input_c)
  state.memory.store(0x1402BD898, input_d)

  simgr = proj.factory.simgr(state)

  simgr.explore(find = 0x1400015B2)

  if simgr.found :
    print(simgr.found[0].solver.eval(input_a, cast_to=bytes).decode())
    print(simgr.found[0].solver.eval(input_b, cast_to=bytes).decode())
    print(simgr.found[0].solver.eval(input_c, cast_to=bytes).decode())
    print(simgr.found[0].solver.eval(input_d, cast_to=bytes).decode())
  else :
    raise Exception('Path not found')
  
if __name__ == '__main__' :
  main(sys.argv)