# mac-address-harvester
Python script to sniff wifi packet traffic for mac addresses and then graph them by vendor in a pie chart.

## Installation
0. git clone git@github.com:gustavemichel/mac-address-harvester.git
0. cd mac-address-harvester/
0. virtualenv venv
0. source venv/bin/activate
0. pip install -r requirements.txt

## Execution
0. source venv/bin/activate
0. sudo airmon-ng start <interface>
0. sudo python macharvest_graph.py <interface>
0. sudo airmon-ng stop <interface>
