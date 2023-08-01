# OPRF-Garbled-Circuits
Different implementations of oblivious pseudo-random functions using (amongst others) the emp-toolkit project. https://github.com/emp-toolkit

## Project Structure
The project is structured into four main folders. One for our implementation of 2HashDH and the Garbled Circuit-based OPRF, both using EMP-Toolkit. 
The second folder PQ-MPC is a fork of https://github.com/encryptogroup/PQ-MPC. Inside, there is the folder pq-oprf that contains an OPRF implementation based on the post-quantum
secure implementation of Garbled Circuits, provided by PQ-MPC. The folder OIDA is a fork of the isogeny-based OPRF from https://github.com/meyira/OIDA and the last folder lattice-OPRF contains the sage scripts from https://ia.cr/2019/1271. The folder final_benchmark_results only contains logs of the benchmarks included in the paper.

## Prerequisits
You have to install cmake, OPENSSL, PKG-Config and Boost via

`sudo apt install cmake libssl-dev pkg-config libboost-all-dev`

Then run 
`git clone`
`cd OPRF-Garbled-Circuits/`
`git submodule init`
`git submodule update`


## Building the Projects

### Building the GC-OPRF and 2HashDH 
`cd GCOPRF-2HashDH`
`git submodule init`
`git submodule update`
`cmake .`
`make`

### Building PQ Version
`cd PQ-MPC`
`git submodule init`
`git submodule update`
`git checkout origin/master`
`cmake .`


### Building OIDA
`cd OIDA/code`
`make`

## WAN Tests
To simulate a WAN test, type 
`sudo tc qdisc add dev lo root  netem  delay 100ms rate 50mbit`
in your linux terminal. This will set the local interface (127.0.0.1) to have rate limit 50mbit and latency 100ms.
To remove the rate limiting from your interface type
`sudo tc qdisc del dev lo root`


## Running the benchmarks

The benchmarks for our C++ implementations of GCOPRF and 2HashDH can
be run by using the run script. The used password is specified in this
file.
Run the GCOPRF benchmark with
`cd GCOPRF-2HashDH`
`./run ./bin/test_user ./bin/test_server X Y`
You can set X to either 128 or 256 to chooses which AES key size you want. Y specifies the number of times the measurment is repeated.
The results of the benchmark are stored in a text file with prefix
`gcoprf_benchmark_results_` followed by the date and time of the run.

Run the 2HashDH benchmark with
`cd GCOPRF-2HashDH`
`./run_2HashDH bin/2HashDH_user bin/2HashDH_server Y`
Y specifies the number of times the measurment is repeated.
The results of the benchmark are stored in a text file with prefix
`2HashDH_benchmark_results_` followed by the date and time of the run.

Run the PQ-MPC protocol by calling
`cd PQ-MPC`
`./bin/user_pq-oprf 1 abc 127.0.0.1 8888 & ./bin/server_pq-oprf 1 8888`

The benchmark of the lattice-based protocol is run a little bit different,
it is a SageMath implementation. Execute
`cd lattice-oprf`
`sage lattice-oprf/ADDS_oprf.sage`
The results of the benchmark are stored in a text file with prefix
`benchmark_results_` followed by the date and time of the run.

Run the isogeny-based protocol by calling
`cd OIDA/code`
`(sleep 0.05; ./client  127.0.0.1 8888) & ./server 8888`





