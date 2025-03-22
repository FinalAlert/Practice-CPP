CXX = g++
CXXFLAGS = -std=c++17 -I/usr/local/include -I/opt/homebrew/include -I/opt/homebrew/include/cryptopp
LDFLAGS = -L/usr/local/lib -L/opt/homebrew/lib -lcryptopp
TARGET = APIcyber

all: $(TARGET)

$(TARGET): APIcyber.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(TARGET) APIcyber.cpp

clean:
	rm -f $(TARGET)
