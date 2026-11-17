# Exploring the AI-RAN

In this experiment, you will bring up an end-to-end 5G network and follow an AI-assisted control loop.

**Start with the [student handout](docs/EXPLORING_AI_RAN.md).** It walks through
capturing connections, decoding E2/E42 messages, inspecting detector reports,
and tracing slice-resource changes and a UE release.

For the article-style browser version, download/open [`docs/index.html`](docs/index.html),
or use the instructor's hosted link. It includes copyable command blocks,
section navigation, and print/PDF styling. GitHub's file view shows HTML source;
the Markdown handout above renders directly on GitHub.

The main experiment explores AI/ML-driven anomaly detection and its use in RAN
slice-resource allocation and RRC connection-release decisions during a DoS
attack. Students operate one run with the saved Random Forest (RF), then one
run with a TCP-aware heuristic as a rule-based baseline for the same control
loop. Both detectors report every computed window to the same xApp policy.

Explicit iperf3, ping, Docker stats, tcpdump, and Hping3 commands let students
trace the control actions and measure throughput, latency/loss, and UPF container
CPU utilization (the paper's Figure 7 metric), with supplementary memory
measurements. CSV results and plots come from the student's own recordings.

## Run on POWDER

Use the profile link supplied by your instructor and reserve one Emulab d430.
The root [`profile.py`](profile.py) selects Ubuntu 22.04 and automatically runs
[`ai-ran/setup.sh`](ai-ran/setup.sh). Preparation installs dependencies, retrieves
pinned source repositories under `/opt`, builds the software, and pulls the
core images. Wait for the node to be **Ready** and its **Startup** state to be **Finished**.

The handout uses fixed entry points in `/opt/ai-ran/bin`. Start each component
when instructed so its initial connection is included in your packet captures.

For profile registration and operating details, see
[setup notes](ai-ran/README.md).

## Repository contents

- `profile.py`, `ai-ran/`: POWDER profile, preparation/runtime scripts, and packet decoders.
- `docs/index.html`, `docs/EXPLORING_AI_RAN.md`: browser and Markdown versions of the student manual.
- [`docs/ai-ran-network.drawio`](docs/ai-ran-network.drawio), [`docs/ai-ran-network.png`](docs/ai-ran-network.png): editable network diagram and the image used in both manuals.
- `conf/`, `slicing-cn/`, `patches/`, `xapp_rc_slice_ctrl.c`: required network configuration and control code.
- `powder/`: pinned images, detector wrapper, and live-measurement analysis helpers.
- `notebooks/`: the saved RF model and preprocessor artifacts.
- `requirements-powder.txt`: pinned host Python dependencies.
- `requirements-comparison.txt`: plotting dependencies for the comparison.

## Credits

Based on [teo-tsou/oai-anomaly-detection](https://github.com/teo-tsou/oai-anomaly-detection)
and Tsourdinis et al., *AI-Driven Network Intrusion Detection and Resource
Allocation in Real-World O-RAN 5G Networks*, ACM MobiCom 2024,
[DOI: 10.1145/3636534.3697311](https://doi.org/10.1145/3636534.3697311).
The teaching workflow is inspired by Fraida Fund's
[Exploring the 5G core network](https://witestlab.poly.edu/blog/exploring-the-5g-core-network/).
