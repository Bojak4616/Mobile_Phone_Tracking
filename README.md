# Mobile_Phone_Tracking
This repository is source code for some of the attacks defined in this paper (https://arxiv.org/pdf/1703.02874v1.pdf)

The attack takes advantage of phones broadcasting probe requests. This can be used to isolate a target and gain information about what their request looks like when defaulting to virtual MAC address probe request broadcasts. Once a fingerprint for the device is created, it can be tracked when on or off WiFi without responding to all requests sniffed on the network.

## Assumptions
This attack assumes the following:
* You know the MAC of the phone you are looking for
* You are in range of your target
* You know if the device is IOS or Android - not required but can help

## Pitfalls
[This paper roughly claims ~80% accuracy on fingerprint techniques.](http://papers.mathyvanhoef.com/asiaccs2016.pdf) Although, it does not take into account combining them together OR how good these techniques are for distinguising seperate devices of the same model. That being said, I'm still not sure how much same device types differ from one another in their probe requests.

More testing needs to be done.

## How to use
```python main.py -h```

## Attack Flow
* Get rMAC (Real MAC Address) from SSID specific Probe Request or if they are connected to an AP. Get sequence number of last packet seen by them
* Wait, or death, for a disconection
* Sniff vMAC (Virtual MAC Address) broadcast probe request
* Save vMAC IE tags
* Listen to all vMACs with same tags and continually refresh tracked sequence number
