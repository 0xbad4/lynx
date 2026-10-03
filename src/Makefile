CXX      := g++
CXXFLAGS := -std=c++23 -Os -ffunction-sections -fdata-sections -Wl,--gc-sections -fno-exceptions -fvisibility=hidden -s -Wextra -I../include

ifdef DEBUG
CXXFLAGS += -g -O0
else
CXXFLAGS += -O2
endif

TEST_DIR  := tests
TOOLS_DIR := tools
BUILD_DIR := bin

.PHONY: clean list

%:
	@if [ -f "$(TEST_DIR)/test_$@.cpp" ]; then \
		mkdir -p $(BUILD_DIR); \
		$(CXX) $(CXXFLAGS) "$(TEST_DIR)/test_$@.cpp" -o "$(BUILD_DIR)/$@"; \
		"$(BUILD_DIR)/$@" $(ARGS); \
	elif [ -f "$(TOOLS_DIR)/$@.cpp" ]; then \
		mkdir -p $(BUILD_DIR); \
		$(CXX) $(CXXFLAGS) "$(TOOLS_DIR)/$@.cpp" -o "$(BUILD_DIR)/$@"; \
		"$(BUILD_DIR)/$@" $(ARGS); \
	else \
		echo "unknown target: $@"; \
		exit 1; \
	fi

list:
	@echo "tests:"
	@ls $(TEST_DIR) | sed -n 's/^test_\(.*\)\.cpp$$/  \1/p'
	@echo "tools:"
	@ls $(TOOLS_DIR) | sed -n 's/^\(.*\)\.cpp$$/  \1/p'

clean:
	rm -rf $(BUILD_DIR)