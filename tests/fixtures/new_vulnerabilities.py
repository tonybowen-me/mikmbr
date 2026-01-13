"""Test fixture with new vulnerability types."""

import pickle
import yaml
import os
import random
import re
import xml.etree.ElementTree as ET

# INSECURE_DESERIALIZATION - pickle
data = pickle.loads(user_input)  # Vulnerable

# INSECURE_DESERIALIZATION - unsafe YAML
config = yaml.load(file_content)  # Vulnerable

# PATH_TRAVERSAL - open with concatenation
filename = user_input
file = open("/var/data/" + filename)  # Vulnerable

# PATH_TRAVERSAL - os.path.join with variable
user_file = request.GET['file']
path = os.path.join("/uploads", user_file)  # Potentially vulnerable

# INSECURE_RANDOM - for token generation
session_token = str(random.randint(1000, 9999))  # Vulnerable

# INSECURE_RANDOM - for password
password = ''.join([str(random.randint(0, 9)) for _ in range(8)])  # Vulnerable

# REGEX_DOS - catastrophic backtracking
pattern = re.compile(r'(a+)+b')  # Vulnerable
pattern2 = re.compile(r'(a*)*b')  # Vulnerable

# XXE - unsafe XML parsing
tree = ET.parse(xml_file)  # Vulnerable
root = ET.fromstring(xml_data)  # Vulnerable
