# Exploring the AI-RAN: AI versus heuristic

A hands-on POWDER lab exploring an AI-assisted 5G RAN control loop: two software
UEs, a sliced core, an OAI RFsim gNB, a FlexRIC near-RT RIC, and an xApp driven by
UPF anomaly detectors.

**Start with the [student handout](docs/EXPLORING_AI_RAN.md).** It walks through
capturing connections, decoding E2/E42 messages, inspecting detector reports,
and tracing slice-resource changes and a UE release.

The main experiment compares the saved Random Forest with a byte-threshold
heuristic using ten-second reports. Matched trials measure
throughput, latency/loss, and UPF container CPU utilization (the paper's Figure 7
metric), with supplementary memory measurements. CSV results and plots are
generated from the student's own run.

## Run on POWDER

Use the profile link supplied by your instructor and reserve one Emulab d430.
The root [`profile.py`](profile.py) selects Ubuntu 22.04 and automatically runs
[`ai-ran/setup.sh`](ai-ran/setup.sh). Preparation installs dependencies, retrieves
pinned source repositories under `/opt`, builds the software, and pulls the
core images. Wait for Startup to finish and `/opt/ai-ran/READY` to exist.

The handout uses fixed entry points in `/opt/ai-ran/bin`. Start each component
when instructed so its initial connection is included in your packet captures.

For profile registration and operating details, see
[setup notes](ai-ran/README.md).

## Repository contents

- `profile.py`, `ai-ran/`: POWDER profile, preparation/runtime scripts, and packet decoders.
- `docs/EXPLORING_AI_RAN.md`: student procedure and lab-report questions.
- `conf/`, `slicing-cn/`, `patches/`, `xapp_rc_slice_ctrl.c`: required network configuration and control code.
- `powder/`: pinned images, detector wrapper, and measurement/evaluation helpers.
- `notebooks/`: the saved model, preprocessor, and test dataset used by the evaluator.
- `requirements-powder.txt`: pinned host Python dependencies.
- `requirements-comparison.txt`: plotting dependencies for the comparison.

## Credits

Based on [teo-tsou/oai-anomaly-detection](https://github.com/teo-tsou/oai-anomaly-detection)
and Tsourdinis et al., *AI-Driven Network Intrusion Detection and Resource
Allocation in Real-World O-RAN 5G Networks*, ACM MobiCom 2024,
[DOI: 10.1145/3636534.3697311](https://doi.org/10.1145/3636534.3697311).
The teaching workflow is inspired by Fraida Fund's
[Exploring the 5G core network](https://witestlab.poly.edu/blog/exploring-the-5g-core-network/).
