# dimy
did i meet you tracing protocol.  

![DIMY Protocol](./demo.png)

![MiTM Attack](./atkdemo.png)

## Bloom

Simple Bloom Filter implementation  

## BFMan

Bloom Filter Manager
- Uses a circular buffer to rotate Daily Bloom Filters  
- Manages the creation and rotation of Query Bloom Filters  

## Dimy

Did I Meet You Protocol Node
- Generates an Ephemeral ID using the elliptical curve Diffie-Hellman key exchange algorithm  
- Splits the Ephemeral ID into shares, distributes the shares + hash of Ephemeral ID over UDP using shamirs secret sharing  
- Receives shares from other nodes  
- Reconstructs shares if num_shares > req_shares to reconstruct a secret  
- Hashes the ephemeral ID to confirm the received ID hashes to the same hash that was received  
- Generates a private key from the Ephemeral ID using a HMAC Key Derivation Function  
- Generates a shared Encounter ID using the private key + Ephemeral ID  
- Encodes the Encounter ID into a Daily Bloom Filter (DBF)  
- Stores a set of Daily Bloom Filters as a Query Bloom Filter (QBF)  
- Uploads Query Bloom Filters to the DimyServer  
- Can trigger a Contact Bloom Filter (CBF)  

## DimyServer

Back-end Server, stores QBFs to check against received CBFs
- Due to the way CBFs are triggered using a signal interrupt, CBFs are 99840 bytes  
- QBFs that are handled through standard TCP socket messaging are 102400 bytes  
- The back-end uses this packet difference to distinguish a CBF from a QBF  
- The server pads a QBF to 102400 bytes with 0 bytes for comparison  
- The comparator only regards 1-bits, with a 10% match indicating a 'close contact' with COVID-19  

## ThreadSafeSocket

ThreadSafe TCP socket, enabling sequential processing of data with no loss due competition on ports  

## Attacker

TBC  
