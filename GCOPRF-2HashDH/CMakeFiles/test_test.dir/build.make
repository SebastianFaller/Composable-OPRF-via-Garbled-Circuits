# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/shf/OPRF-Garbled-Circuits/old_implementation

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/shf/OPRF-Garbled-Circuits/old_implementation

# Include any dependencies generated for this target.
include CMakeFiles/test_test.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/test_test.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/test_test.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/test_test.dir/flags.make

CMakeFiles/test_test.dir/test.cpp.o: CMakeFiles/test_test.dir/flags.make
CMakeFiles/test_test.dir/test.cpp.o: test.cpp
CMakeFiles/test_test.dir/test.cpp.o: CMakeFiles/test_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/shf/OPRF-Garbled-Circuits/old_implementation/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/test_test.dir/test.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/test_test.dir/test.cpp.o -MF CMakeFiles/test_test.dir/test.cpp.o.d -o CMakeFiles/test_test.dir/test.cpp.o -c /home/shf/OPRF-Garbled-Circuits/old_implementation/test.cpp

CMakeFiles/test_test.dir/test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_test.dir/test.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/shf/OPRF-Garbled-Circuits/old_implementation/test.cpp > CMakeFiles/test_test.dir/test.cpp.i

CMakeFiles/test_test.dir/test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_test.dir/test.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/shf/OPRF-Garbled-Circuits/old_implementation/test.cpp -o CMakeFiles/test_test.dir/test.cpp.s

CMakeFiles/test_test.dir/garbling-scheme.cpp.o: CMakeFiles/test_test.dir/flags.make
CMakeFiles/test_test.dir/garbling-scheme.cpp.o: garbling-scheme.cpp
CMakeFiles/test_test.dir/garbling-scheme.cpp.o: CMakeFiles/test_test.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/shf/OPRF-Garbled-Circuits/old_implementation/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/test_test.dir/garbling-scheme.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/test_test.dir/garbling-scheme.cpp.o -MF CMakeFiles/test_test.dir/garbling-scheme.cpp.o.d -o CMakeFiles/test_test.dir/garbling-scheme.cpp.o -c /home/shf/OPRF-Garbled-Circuits/old_implementation/garbling-scheme.cpp

CMakeFiles/test_test.dir/garbling-scheme.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_test.dir/garbling-scheme.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/shf/OPRF-Garbled-Circuits/old_implementation/garbling-scheme.cpp > CMakeFiles/test_test.dir/garbling-scheme.cpp.i

CMakeFiles/test_test.dir/garbling-scheme.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_test.dir/garbling-scheme.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/shf/OPRF-Garbled-Circuits/old_implementation/garbling-scheme.cpp -o CMakeFiles/test_test.dir/garbling-scheme.cpp.s

# Object files for target test_test
test_test_OBJECTS = \
"CMakeFiles/test_test.dir/test.cpp.o" \
"CMakeFiles/test_test.dir/garbling-scheme.cpp.o"

# External object files for target test_test
test_test_EXTERNAL_OBJECTS =

bin/test_test: CMakeFiles/test_test.dir/test.cpp.o
bin/test_test: CMakeFiles/test_test.dir/garbling-scheme.cpp.o
bin/test_test: CMakeFiles/test_test.dir/build.make
bin/test_test: /usr/lib/x86_64-linux-gnu/libssl.so
bin/test_test: /usr/lib/x86_64-linux-gnu/libcrypto.so
bin/test_test: emp-tool/libemp-tool.so
bin/test_test: CMakeFiles/test_test.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/shf/OPRF-Garbled-Circuits/old_implementation/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable bin/test_test"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_test.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/test_test.dir/build: bin/test_test
.PHONY : CMakeFiles/test_test.dir/build

CMakeFiles/test_test.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/test_test.dir/cmake_clean.cmake
.PHONY : CMakeFiles/test_test.dir/clean

CMakeFiles/test_test.dir/depend:
	cd /home/shf/OPRF-Garbled-Circuits/old_implementation && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/shf/OPRF-Garbled-Circuits/old_implementation /home/shf/OPRF-Garbled-Circuits/old_implementation /home/shf/OPRF-Garbled-Circuits/old_implementation /home/shf/OPRF-Garbled-Circuits/old_implementation /home/shf/OPRF-Garbled-Circuits/old_implementation/CMakeFiles/test_test.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/test_test.dir/depend

