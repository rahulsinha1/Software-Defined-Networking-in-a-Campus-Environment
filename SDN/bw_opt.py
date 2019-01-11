from mininet.node import Controller,RemoteController,OVSController
from functools import partial
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.cli import CLI


net=Mininet(host=CPULimitedHost, link=TCLink)

        # Add hosts and switches
c0=net.addController(name='poxController',controller=RemoteController,ip='127.0.0.1', port=6633)
h1 = net.addHost( 'h1')
h2 = net.addHost( 'h2')
h3 = net.addHost( 'h3' )
h4 = net.addHost( 'h4' )

s1 = net.addSwitch( 's1' )
s2 = net.addSwitch( 's2' )
s3 = net.addSwitch( 's3' )
s4 = net.addSwitch( 's4' )


        # Add links                                                                                                                                    
net.addLink( s1, h1,bw=1, delay='5ms', max_queue_size=1000, loss=5, use_htb=True )

net.addLink( s1, h2,bw=10, delay='15ms', max_queue_size=1000, loss=10, use_htb=True )
net.addLink( s4, h3,bw=320, delay='0ms', max_queue_size=1000, loss=0, use_htb=True)

net.addLink( s4, h4, bw=200, delay='0ms', max_queue_size=1000, loss=0, use_htb=True)

net.addLink(s1, s2, bw=200, delay='0ms', max_queue_size=1000, loss=0, use_htb=True)
net.addLink(s1, s3, bw=320, delay='0ms', max_queue_size=1000, loss=0, use_htb=True)

net.addLink(s3, s4, bw=200, delay='0ms', max_queue_size=1000, loss=0, use_htb=True)

net.addLink(s2, s4, bw=320, delay='0ms', max_queue_size=1000, loss=0, use_htb=True)
net.start()
CLI(net)
                  
