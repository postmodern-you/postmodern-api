import os
import sys

# Make the top-level wire/pcm modules importable when running the tests from a source
# checkout without an editable install.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
