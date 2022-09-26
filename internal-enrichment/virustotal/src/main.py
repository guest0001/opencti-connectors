# -*- coding: utf-8 -*-
"""VirusTotal connector main file."""

from virustotal import VirusTotalConnector

if __name__ == "__main__":
    connector = VirusTotalConnector()
    #connector.start()
    connector._process_file_graph({"name": [],"entity_type": "StixFile","id": "039a52ae-d594-479d-968e-caf5d8cef75d","observable_value": '42029d1434c7f8b8e9aedd4f460da0d34186ea76b7581e1bacefa3b3923dca59',"standard_id": "file--0919132d-bbcb-5484-9754-a8c3141bb954"})
