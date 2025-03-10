# IPMerge

A Python tool for merging CIDR blocks of IPv4 and IPv6 addresses.

## Features

- Merge identical, adjacent or overlapping CIDR blocks
  - Firewall table optimization
- Support for dual notation of IPv6 addresses (both input and output)
  - Output is modifiable by CLI options
- Easily extensible/modifiable to any address type that can be written in CIDR notation

## Example

Input:

```txt
192.168.0.0/24
192.168.1.0/24
192.168.0.1
192.168.2.0/23
```

Output:

```txt
192.168.0.0/22
```

## Installation

### PipX (Preferred)

After installing pipx (See [pipx installation instructions](https://pipx.pypa.io/stable/installation/)), run the following command:

```sh
pipx install ipmerge
```

### Pip

Normal installation through PIP is also available:

```sh
pip install ipmerge
```

## Usage

After [installation](#installation), you should be able to invoke ipmerge from the command line.

```sh
ipmerge
```

IPMerge expects a one or more input files formatted according to instructions in [Input formatting](#input-formatting).
Input files are passed to the tool as arguments.
For example, the following will invoke the tool on input files "in1.txt" and "in2.txt":

```sh
ipmerge in1.txt in2.txt
```

Note that file extensions don't matter, the tool will attempt to parse any file given to it.
The tool will read the input files, parse any blocks of IP addresses found inside, merge them and output the result on the command line.

### Output into a file

If you want to output into a file instead of the command line, you can specify the output file using the `-o [file]` option.

```sh
ipmerge in1.txt in2.txt -o out.txt
```

### Read input from command line

IPMerge also supports taking input from the command line, which can be achieved by using the flag `-`.

```sh
ipmerge -
```

The input is then read from `stdin`, which enables the tool to take input from pipes and the command line.

The input is terminated by an EOF character.
If you're feeding input through pipes, you don't have to worry about that, closing of a pipe emits EOF automatically.
If you're entering input manually by keyboard into the command line, see documentation of your OS, terminal or terminal emulator on how you can insert an EOF character into your command line. (On Linux it's usually `CTRL+D`)

This can be combined with other input files.
For example the following command will load data from files `in1.txt` and `in2.txt` and also from the command line.

```sh
ipmerge in1.txt in2.txt -
```

Note that the reading is done in the specified sequence, therefore specifying the `-` flag before input files will defer the reading of those files to after the input from the command line or `stdin` is read. The flag can be specified multiple times to read from the command line or `stdin` multiple times (through multiple EOFs).

### Other options

For more options, see the help section by invoking either of the following commands.

```sh
ipmerge -h
ipmerge --help
```

### Input formatting

The input of the tool consists of CIDR blocks of IPv4 or IPv6 addresses. One block per line is expected.
Empty lines and leading and trailing whitespaces are ignored.

Example of a valid input:

```txt
192.168.0.0/24

192.168.1.0/24
192.168.8.0/21

::FFFF:0:0:0/80
```

#### Comments

The `#` character can be used in input as a line comment. Anything on the line after this character is ignored.

```txt
# this is a comment
192.168.0.0/24  # this is also a comment

# The following address is ignored:
# 192.168.1.0/24
```

#### Host addresses

If a prefix of a block is omitted, the address is assumed to be a host address.
The following lines are therefore equivalent and will parse to the same result.

```txt
192.168.0.1/32
192.168.0.1
```

#### Invalid input

When the tool encounters input that it doesn't recognize as a valid block, it terminates with an error, which is printed into `stderr`.
When taking input from the command line (`stdin`), the program terminates immediately after taking the offending line.
For users that use this tool programmatically, see [exceptions](./src/ipmerge/address/exceptions.py) thrown by this tool internally.

The following is a non-exhaustive list of invalid input types with examples:

- Any input that isn't a valid address of any of the supported address types
  - `a.a.a`
  - `256.0.0.1`
  - `hello`
- Any prefix that is invalid for an associated address type
  - `192.168.0.0/33`
  - `::/129`
  - `::/-1`
- Any block, whose address isn't a valid network address for the specified prefix length
  - `192.168.0.1/24`
  - `172.16.1.0/23`
  - `::1/127`

## License

Project is licensed under the MIT License (see [LICENSE](./LICENSE))
