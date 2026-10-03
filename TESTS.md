# Tests

This project builds and runs tests from `src/tests` and command-line tools from `src/tools` through the single `src/Makefile`.

## Build and execution model

From `src/`:

```bash
make list
```

This prints the available targets, splitting them into:

- tests: `test_<name>`
- tools: `<tool-name>`

Each target is built automatically from the matching source file:

- `src/tests/test_<name>.cpp` -> test target `<name>`
- `src/tools/<tool>.cpp` -> tool target `<tool>`

Example:

```bash
make utils
make linklayer
make arpup
```

The same pattern is used for all generated binaries under `src/bin/`.

## Compiler settings

The Makefile uses:

```bash
CXX := g++
CXXFLAGS := -std=c++23 -Os -ffunction-sections -fdata-sections -Wl,--gc-sections -fno-exceptions -fvisibility=hidden -s -Wextra -I../include
```

Optional debug build:

```bash
make DEBUG=1 utils
```

This adds `-g -O0` while leaving the normal optimized flags in place.

## Passing arguments to tests/tools

The Makefile supports runtime args via `ARGS`:

```bash
make test_utils ARGS="--help"
make arpup ARGS="-i eth0 -t 192.168.1.10"
```

This is useful for tool invocations and for tests that may accept runtime options.

## Cleanup

```bash
make clean
```

removes the generated binaries from `src/bin/`.

## Practical workflow

Typical local workflow:

```bash
cd src
make list
make utils
make linklayer
```

For tools:

```bash
cd src
make arpup ARGS="-i eth0 -t 192.168.1.10"
```

This project keeps the same test/tool pattern across additions, so new `.cpp` files under `src/tests` or `src/tools` can be added without changing the build conventions.
