# mac-address-harvester
Python script to sniff wifi packet traffic for mac addresses and then graph them by vendor in a pie chart.

## Installation
```
git clone git@github.com:gustavemichel/mac-address-harvester.git
cd mac-address-harvester/
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Execution
```
source venv/bin/activate
sudo airmon-ng start <interface>
sudo python macharvest_graph.py <interface>
sudo airmon-ng stop <interface>
```
