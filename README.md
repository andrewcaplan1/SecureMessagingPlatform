# Secure Messaging Platform

Uses SPEKE for mutual password based authentication and Kerberos for session key distribution.

## Client Usage

Users enter their username and password when prompted by the client program. If the password is incorrect, the DH
exchange will fail, and the user will be re-prompted for their password. Note that usernames are case-insensitive.
If someone has already logged into the KDC with the given username, the KDC will block the new sign-in request.

Users have these commands:

- `list`
- `send username message ...`
- `logout`

`lists` asks the KDC server for the usernames of all online clients. `send` sends the target user the specified
message. For example, `send Bob Hello World!` will send "Hello World!" to Bob's workstation. `logout`
un-authenticates with the KDC, so the user must retype their username and password to re-authenticate.

## Testing

We did not implement client registration, so here are some pre-registered dummy users for testing:

- Andrew : HardPassword123
- Amanda : PasswordHard321
- Bob : LiveLoveNetSec123

To see this program in action, run ...

1. `./kdc.py`
2. `./client.py` and sign in with Andrew's credentials.
3. `./client.py` and sign in with Amanda's credentials.

Message types recognized by the KDC:

- SIGN-IN, for client authentication
- LIST, for listing online users
- MSG-AUTH, for establishing shared client keys
- MESSAGE, for sending messages between clients

## Known Issues

- issue with [p, 2-p] small something attack from wikipedia
- if client-client messages are received out of order, destination user won't receive ticket-to-B
- if implementing client registration, need to make sure no one can register with the name 'kdc'
- trying to message a person who is not online?

Authentication Steps

client starts up
put username and password
WS calculates W and stores it
WS chooses a and stores it

- Expirations for session keys are created and sent but no implementation yet to actually check validity, but assume
  that they would be given more time for the assignment

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
   WS —> KDC : A, W<sup>a</sup> mod p

2. init-auth-resp
   KDC -> WS: W<sup>m</sup> mod p, SA-KDC{C1, timestamp}

3. Both calculate and store the shared key: S<sub>A-KDC</sub> = W<sup>a*m</sup> mod p

4. init-chal-req
   KDC -> WS:S<sub>A-KDC</sub>{timestamp}

5. init-chal-resp
   KDC creates Challenge 1 (C1), and stores it

Message other clients

1. msg-auth
   WS -> KDC: TGT, S<sub>A-KDC</sub>{B, timestamp}
2. msg-auth (response)
   KDC -> WS: Ticket-to-B, S<sub>A-KDC</sub>{B, timestamp, K<sub>AB</sub>, K<sub>AB</sub>-Expiration}
3. message
   WS -> B: Ticket-to-B, S<sub>AB</sub>{message, timestamp}
