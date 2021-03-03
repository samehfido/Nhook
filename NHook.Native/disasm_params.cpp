#define unique

unique int       ideal;                // Force IDEAL decoding mode
unique int       lowercase;            // Force lowercase display
unique int       tabarguments;         // Tab between mnemonic and arguments
unique int       extraspace;           // Extra space between arguments
unique int       putdefseg;            // Display default segments in listing
unique int       showmemsize;          // Always show memory size
unique int       shownear;             // Show NEAR modifiers
unique int       shortstringcmds;      // Use short form of string commands
unique int       sizesens;             // How to decode size-sensitive mnemonics
unique int       symbolic;             // Show symbolic addresses in disasm
unique int       farcalls;             // Accept far calls, returns & addresses
unique int       decodevxd;            // Decode VxD calls (Win95/98)
unique int       privileged;           // Accept privileged commands
unique int       iocommand;            // Accept I/O commands
unique int       badshift;             // Accept shift out of range 1..31
unique int       extraprefix;          // Accept superfluous prefixes
unique int       lockedbus;            // Accept LOCK prefixes
unique int       stackalign;           // Accept unaligned stack operations
unique int       iswindowsnt;          // When checking for dangers, assume NT

#undef unique