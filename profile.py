"""Exploring the AI-RAN

One d430 running an OAI RFsim RAN, two software UEs, a sliced 5G core,
FlexRIC near-RT RIC, and an anomaly-driven control xApp.

Instructions:
Wait for Startup to finish. Preparation installs packages, clones pinned
repositories under /opt, builds the software, and pulls the core images.

Follow /opt/oai-anomaly-detection/docs/EXPLORING_AI_RAN.md.
Setup progress: sudo tail -f /var/log/ai-ran/setup.log
Successful preparation creates /opt/ai-ran/READY.

This is a repository-based profile: the repository must contain this root
profile.py and ai-ran/setup.sh. No radio-frequency reservation is needed.

References:
- T. Tsourdinis, N. Makris, T. Korakis, and S. Fdida, “AI-Driven
Network Intrusion Detection and Resource Allocation in Real-World
O-RAN 5G Networks,” in Proceedings of the 30th Annual
International Conference on Mobile Computing and Networking, pp.
1842–1849, 2024.
- https://github.com/teo-tsou/oai-anomaly-detection/
"""

import geni.portal as portal
import geni.rspec.pg as pg

pc = portal.context
request = pc.makeRequestRSpec()
node = request.RawPC("ai-ran")
node.component_manager_id = "urn:publicid:IDN+emulab.net+authority+cm"
node.hardware_type = "d430"
node.disk_image = "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU22-64-STD"
node.addService(pg.Execute(shell="bash", command="sudo /bin/bash /local/repository/ai-ran/setup.sh"))
pc.printRequestRSpec()
