# Reproduction

Requires macOS with Seatbelt and Python 3.11 or newer. From this directory run:

```sh
python3 -m unittest discover -s tests -v
python3 -m forge_permit --output review-demo-output
```

The demo requires loopback access and macOS sandbox support. It uses only synthetic fixtures; it does not require model downloads or internet access. The output path must not already exist. These instructions describe a fresh reproduction, distinct from the prior observations in `observed-evidence.json`.
