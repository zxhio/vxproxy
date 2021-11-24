CXX = g++
CXXFLAGS = -std=c++11 -march=native -O0 -g -Wall -Werror -I../include
LDFLAGS = -static -lpthread

SRCS = \
	ChecksumTest.cpp \
	TCPIPOptionTest.cpp \

OBJS = $(patsubst %.cpp, %.o, $(SRCS))
DEPS = $(patsubst %.cpp, %.d, $(SRCS))
TARGETS = $(patsubst %.cpp, %, $(SRCS))

all: $(TARGETS)

$(TARGETS): $(OBJS)
	$(CXX) $(CXXFLAGS) $@.o -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

%.d: %.cpp
	@ $(CXX) $(CXXFLAGS) -MM $< > $@

.PHONY: clean
clean:
	rm -rf $(TARGETS) $(OBJS) $(DEPS)

-include $(DEPS)