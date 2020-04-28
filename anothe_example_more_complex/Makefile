.PHONY: all clean copy format

CXX=x86_64-w64-mingw32-g++-win32 
OFLAGS=-O3 -Wall -DNDEBUG
LDFLAGS= -static-libgcc -static-libstdc++  -lbcrypt  

SOURCES=hash.cpp main.cpp
HEADERS=hash.h
EXECUTABLE=hash.exe
SHAREDIR=~/shared/exec/


$(SHAREDIR)$(EXECUTABLE): $(EXECUTABLE)
	cp -f $(EXECUTABLE) $(SHAREDIR)

$(EXECUTABLE): $(SOURCES)
	$(CXX)  $(SOURCES)  -o $(EXECUTABLE) $(OFLAGS) $(LDFLAGS)

format:
	astyle $(SOURCES) $(HEADERS)
clean:
	rm -f $(EXECUTABLE) *.orig