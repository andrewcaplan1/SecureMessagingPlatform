# SecureMessagingPlatform


List of valid message types:
- LIST
- SIGN-IN
- MESSAGE


Known Issues
- issue with [p, 2-p] small something attack from wikipedia
- if client-client messages are received out of order, destination user won't receive ticket-to-B

Authentication Steps

client starts up
put username and password
WS calculates W and stores it
WS chooses a and stores it

Init-auth-req
WS—>KDC : A, W^a mod p

—————————

KDC receives init-auth-req
KDC calculates W for that user and stores it
KDC chooses m and stores it
KDC computes SA-KDC = (Wa mod p)m mod p
KDC stores SA-KDC
KDC forgets W,m
KDC creates Challenge 1 (C1), and stores it
**come back to this: abort if value received is not in range [2,p-2]**

Init-auth-resp
KDC → WS: Wm mod p, SA-KDC{C1, timestamp}

—————————

WS receives Init-auth-resp

WS computes SA-KDC = (Wm mod p)a mod p
WS stores SA-KDC
WS forgets W, a
WS solves challenge C1
WS creates Challenge 2 (C2), and stores it

Init-chall-resp-1
WS → KDC: SA-KDC{C1, C2, timestamp}

—————————

KDC receives Init-chall-resp

KDC validates C1 challenge response
KDC solves challenge C2
KDC creates TGT = KKDC { A, timestamp, time-until-expire }

Init-final
KDC → SA-KDC{C2, TGT, timestamp}

—————————
~ Now A can use the TGT within the timeframe to try to start messaging with another client, B ~
