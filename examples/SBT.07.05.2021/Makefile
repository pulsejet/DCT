# on a mac need to set PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
# the code *requires* C++ 20 or later

INCLUDES = ../../include
CXXFLAGS = -g -O0 -I. -I$(INCLUDES) -Wall -Wextra -std=c++20 -I/opt/local/include
CXXFLAGS += $(shell pkg-config --cflags libndn-ind)
CXXFLAGS += -fsanitize=address,undefined
# fmt uses <codecvt> which was deprecated with no replacement
CXXFLAGS += -Wno-deprecated-declarations 
LIBS = -L/opt/local/lib $(shell pkg-config --libs libndn-ind)
HDRS = sbtShim.hpp
DEPS = $(HDRS)
BINS = sbtAdaptor
JUNK = 

# OS dependent definitions
ifeq ($(shell uname -s),Darwin)
CXX=clang++
# we can't fix boost warnings so suppress them
CXXFLAGS += --system-header-prefix=boost/
CXXFLAGS += -fsanitize=address,undefined
LIBS += -lboost_iostreams-mt -llog4cxx -lsodium -lcrypto
JUNK += $(addsuffix .dSYM,$(BINS))
else
CXX=c++
LIBS += -lboost_iostreams -llog4cxx -lpthread -lsodium -lcrypto
endif

#all: $(BINS)
all: sbtAdaptor

.PHONY: clean distclean tags

sbtAdaptor: sbtAdaptor.cpp $(DEPS)
	$(CXX) $(CXXFLAGS) -o $@ $< $(LIBS)

clean:
	rm -rf $(BINS) $(JUNK)

distclean: clean
