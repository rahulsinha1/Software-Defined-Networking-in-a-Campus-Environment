from pox.core import core

block_ports = set()

def block_handler (event):

  tcpp = event.parsed.find('tcp')
  if not tcpp: return # Not TCP
  if tcpp.srcport in block_ports or tcpp.dstport in block_ports:

    core.getLogger("blocker").debug("Blocked TCP %s <-> %s",
                                    tcpp.srcport, tcpp.dstport)
    event.halt = True

def unblock (*ports):
  block_ports.difference_update(ports)

def block (*ports):
  block_ports.update(ports)

def launch (ports = ''):


  block_ports.update(int(x) for x in ports.replace(",", " ").split())


  core.Interactive.variables['block'] = block
  core.Interactive.variables['unblock'] = unblock

  core.openflow.addListenerByName("PacketIn", block_handler)

