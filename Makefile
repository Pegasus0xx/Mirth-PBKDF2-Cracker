CXX      = g++
CXXFLAGS = -std=c++20 -O2 -Iinclude
LIBS     = -lcryptopp
TARGET   = MirthCrack
SRC      = src/main.cpp src/base64.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)