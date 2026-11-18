# -*- coding: utf-8 -*-
"""Exploring the AI-RAN

In this experiment, you will bring up an end-to-end 5G network and follow an AI-assisted control loop.

Instructions:
Wait for the node to be Ready, then connect using the portal's SSH command.
Follow /local/repository/README.md to install dependencies, build OAI and
FlexRIC, and start the network yourself.

This repository-based profile allocates one Ubuntu 22.04 server. It runs no
lab setup script. No radio-frequency reservation is needed for RFsim.

"""

import geni.portal as portal

pc = portal.context
request = pc.makeRequestRSpec()
node = request.RawPC("ai-ran")
node.component_manager_id = "urn:publicid:IDN+emulab.net+authority+cm"
node.hardware_type = "d430"
node.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD"
pc.printRequestRSpec()
