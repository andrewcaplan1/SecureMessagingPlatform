# Secure Messaging Platform

SPEKE for password based authentication and Kerberos for session key distribution.

users:
Andrew: HardPassword123
Amanda: PasswordHard321

Message types recognized by the KDC:
- SIGN-IN, for client authentication
- LIST, for listing online users
- MSG-AUTH, for establishing shared client keys
- MESSAGE, for sending messages between clients






## Known Issues
- issue with [p, 2-p] small something attack from wikipedia
- if client-client messages are received out of order, destination user won't receive ticket-to-B
- if implementing client registration, need to make sure no one can register with the name 'kdc'

Authentication Steps

client starts up
put username and password
WS calculates W and stores it
WS chooses a and stores it

## Protocol

### Assumptions

Assume that the KDC has a list of registered users and their hashed passwords.

- A is Alice's username
- a is Alice's randomly generated Diffie-Hellman secret
- m is the KDC's randomly generated Diffie-Hellman secret
- a and m are forgotten after the Diffie-Hellman exchange (step 3)
- p is the public safe prime 1299827
- W is Alice's password
- g is SHA-256(W)<sup>2</sup>

—————————

1. init-auth-req
WS—>KDC : A, W<sup>a</sup> mod p

2. init-auth-resp
KDC → WS: W<sup>m</sup> mod p, SA-KDC{C1, timestamp}

3. Both calculate and store the shared key: S<sub>A-KDC</sub> = W<sup>a*m</sup> mod p

4. 
KDC creates Challenge 1 (C1), and stores it


Init-auth-resp
KDC → WS: Wm mod p, SA-KDC{C1, timestamp}

—————————

WS receives init-auth-resp

WS computes SA-KDC = (Wm mod p)a mod p
WS stores SA-KDC
WS forgets W, a
WS solves challenge C1
WS creates Challenge 2 (C2), and stores it

init-chal-resp-1
WS → KDC: SA-KDC{C1, C2, timestamp}

—————————

KDC receives init-chal-resp

KDC validates C1 challenge response
KDC solves challenge C2
KDC creates TGT = KKDC { A, timestamp, time-until-expire }

Init-final
KDC → SA-KDC{C2, TGT, timestamp}

—————————
~ Now A can use the TGT within the timeframe to try to start messaging with another client, B ~
