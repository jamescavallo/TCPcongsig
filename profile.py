"""Test profile for congestion experiments (specifically for emulab testbed)

Instructions:
Wait for the profile instance to start, and then log in hosts.
"""

import geni.portal as portal
import geni.rspec.pg as rspec

pc = portal.Context()
pc.defineParameter( "n", "Latency", portal.ParameterType.LATENCY, 10 )
params = portal.context.bindParameters()
if params.n < 1:
    pc.reportError( portal.ParameterError( "You must choose a value for latency", ["n"] ) )
pc.verifyParameters()

request = portal.context.makeRequestRSpec()

HARDWARE_TYPE = 'd710'
OS_IMAGE = 'urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU20-64-STD'

xin = request.RawPC("in")
xin.hardware_type = HARDWARE_TYPE
xin.disk_image = OS_IMAGE

xrouter1 = request.RawPC("router1")
xrouter1.hardware_type = HARDWARE_TYPE
xrouter1.disk_image = OS_IMAGE

xin_xrouter1 = request.Link(members = [xin, xrouter1])

xcross1 = request.RawPC("cross1")
xcross1.hardware_type = HARDWARE_TYPE
xcross1.disk_image = OS_IMAGE

xcross1_xrouter1 = request.Link(members = [xcross1, xrouter1])

xrouter2 = request.RawPC("router2")
xrouter2.hardware_type = HARDWARE_TYPE
xrouter2.disk_image = OS_IMAGE

xrouter1_xrouter2 = request.Link(members = [xrouter1, xrouter2])

xout = request.RawPC("out")
xout.hardware_type = HARDWARE_TYPE
xout.disk_image = OS_IMAGE

xrouter2_xout = request.Link(members = [xrouter2, xout])

xcross2 = request.RawPC("xcross2")
xcross2.hardware_type = HARDWARE_TYPE
xcross2.disk_image = OS_IMAGE

xrouter2_xcross2 = request.Link(members = [xrouter2, xcross2])

portal.context.printRequestRSpec()
