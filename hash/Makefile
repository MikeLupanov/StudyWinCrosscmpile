.PHONY: all clean copy

CXX=x86_64-w64-mingw32-g++-win32

OFLAGS=-O3 -Wall -DNDEBUG
## for static build
LDFLAGS=-static-libgcc -static-libstdc++ -ladvapi32 
## for dynamic build
##LDFLAGS=-ladvapi32

SOURCES=hash.cpp
EXECUTABLE=hash.exe
##SHAREDIR=~/shared/exec/

## copy to Windows share folder
##$(SHAREDIR)$(EXECUTABLE): $(EXECUTABLE)
##	cp -f $(EXECUTABLE) $(SHAREDIR)

## buld exe
$(EXECUTABLE): $(SOURCES)
	$(CXX) $(LDFLAGS) $(SOURCES) -o $(EXECUTABLE) $(OFLAGS) 


clean:
	rm -f $(EXECUTABLE) 