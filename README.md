# SDS
Software Distribution Service (C++)

##Summary
A Secure Distribution Framework between a Client and Server, that will directly receive and map encrypted modules directly into memory without the need to map anything on the hard drive. Masks any network connection and data sent and received using WinAPI. 

#Specifics
- Multithreaded TCP Server that will send you a specific DLL/Module to be loaded into your target process.
- Byte data sent over a network using the TCP protocol and Windows Socket API (WSA).
- Client map the DLL/Module into the target process memory and spawns a thread.
- DLL/Module data is never saved on the hard drive only memory.

#In-Development
- Have not decided whether I want to add any authentication since it is rather trivial and there are multiple frameworks that allow you to access a database via SQL.
- Encryption.
- General Improvements.
