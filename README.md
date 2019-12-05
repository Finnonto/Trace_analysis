# Trace Analysis

This project analizes flows of trace files and outputs to charts.

## Dependency

* The file **_analysis.py_** uses python3, needs kits: dpkt, plotly

```bash
sudo apt install python3-pip
pip3 install dpkt
pip3 install plotly
```

## How To Use

* **_analysis.py_** :

```bash
python3 analysis.py <trace file>  <attack list(or 'none')> <mode:sec/min/hour/real> <time interval(sec)>
```

![Chart](https://github.com/LycorisAurea/trace_analysis/show/sep_Analysis_60s_AppDDos.html)
