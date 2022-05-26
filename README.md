# Toy-Stream-Cipher-Implementation
Prerequisites: Install ZeroMQ and Libtomcrypt

SHA-256 from Libtomcrypt is used as a deterministic PRNG function. To avoid repeating of the keys, the state is used. In this implementation, a counter is used to prpvide stateful implementation of teh PRNG.

Alice code:
1. Alice reads "HW1PlaintextTest.txt"
2. Alice examines "sharedSecret.txt" for the shared key.
3. Alice hashes the content of “HW1PlaintextTest.txt” file and prints it in the terminal (shown in Hex).
4. Alice computes ciphertext and saves it as "TheCiphertext.txt" (write it in Hex with no spaces between ciphertexts).
5. Create a string consisting of Hash + Ciphertexts, and then send it via ZeroMQ.

Bob code: 
1. Bob examines "sharedSecret.txt" for the shared key.
2. Bob computes the ciphertext's plaintext. Write plaintext to "BobPlaintext.txt"
3. Bob compares the plaintext and received hash. Write "Hashes successfully match" to "Bob h.txt"

