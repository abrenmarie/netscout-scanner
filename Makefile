CXX ?= g++
CXXFLAGS ?= -std=c++11 -O2 -Wall -Wextra -Wpedantic
THREAD_FLAGS := -pthread

TARGET := netscout
SRCS := main.cpp scanner.cpp
OBJS := $(SRCS:.cpp=.o)

TEST_CIDR := tests/test_cidr

.PHONY: all clean test test-unit test-integration

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) $(THREAD_FLAGS) -o $@ $(OBJS)

%.o: %.cpp scanner.h
	$(CXX) $(CXXFLAGS) $(THREAD_FLAGS) -c $< -o $@

$(TEST_CIDR): tests/test_cidr.cpp scanner.cpp scanner.h
	$(CXX) $(CXXFLAGS) $(THREAD_FLAGS) -I. \
		tests/test_cidr.cpp scanner.cpp -o $@

test-unit: $(TEST_CIDR)
	./$(TEST_CIDR)

test-integration: $(TARGET)
	python3 tests/test_scanner.py

test: test-unit test-integration

clean:
	rm -f $(TARGET) $(OBJS) $(TEST_CIDR)