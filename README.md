# IoT-5G_project

In this project we implement a security protocol for Wake-up radio enabled devices in a Wireless Sensor Network scenario related to the 
world of agriculture without greatly undermining the performances or the power optimization. We also implemented an authentication protocol for
D2D communication between nodes, inspired by Kerberos. For more information please see the report in this repository.

## Dependencies

In order to run this project the following packages are necessary:
* pycrypto 2.6.1 or higher
* colorama 0.4.3 or higher (replaceable with ANSI color escape sequences)

## Usage

1. Run the bs.py file
2. Run the ch.py file with the options:
  + --port: specify the socket port to be used
  + --key: bytestring of length 16 that is used as key
3. Run a different ch.py file with the same aforementioned options, but with different values
4. Run the sensor.py file to start the program

For every file the debug -o option can be used to show debug information like the values sent over the socket.
