from flask import request
import lxml.etree as ET
def parse():
    data = request.data
    parser = ET.XMLParser(resolve_entities=True)   # external entities enabled
    return ET.fromstring(data, parser)             # XXE; not a taint sink in our ruleset
