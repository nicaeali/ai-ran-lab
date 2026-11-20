# -*- coding: utf-8 -*-
"""Exploring the AI-RAN

In this experiment, you will bring up an end-to-end 5G network and follow an AI-assisted control loop.

Instructions:
Follow the instructions at [AI RAN lab](https://github.com/nicaeali/ai-ran-lab/blob/main/README.md) to run this experiment.

"""

import geni.portal as portal

pc = portal.context
request = pc.makeRequestRSpec()
node = request.RawPC("ai-ran")
node.component_manager_id = "urn:publicid:IDN+emulab.net+authority+cm"
node.hardware_type = "d430"
node.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD"
pc.printRequestRSpec()
