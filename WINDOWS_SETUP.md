# Windows Setup

Install Node.js 18 or later. No C++ compiler, Python, or external npm module is needed. Open Git Bash or PowerShell in the project directory and run:

```sh
npm install
npm start -- ./test_dpi.pcap ./filtered.pcap --block-app YouTube
```

For a JSON summary without writing an output capture:

```sh
npm start -- ./test_dpi.pcap --json
```

`filtered.pcap` is a binary capture file. Open it with Wireshark to inspect packet rows; a text editor cannot display it as source text. This analyzer filters saved captures and does not block live Edge/Chrome traffic. See [README.md](README.md) for the module map and supported formats.
