# CMake generated Testfile for 
# Source directory: /home/shf/OPRF-Garbled-Circuits/old_implementation
# Build directory: /home/shf/OPRF-Garbled-Circuits/old_implementation
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_hash2Curve "/home/shf/OPRF-Garbled-Circuits/old_implementation/bin/hash2Curve_test")
set_tests_properties(test_hash2Curve PROPERTIES  _BACKTRACE_TRIPLES "/home/shf/OPRF-Garbled-Circuits/old_implementation/CMakeLists.txt;55;add_test;/home/shf/OPRF-Garbled-Circuits/old_implementation/CMakeLists.txt;0;")
subdirs("emp-tool")
