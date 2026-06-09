# Student Task: ECDSA Nonce Reuse

## Goal

Recover the private key from two ECDSA signatures that reused the same nonce `k`.

Then sign:

```text
role=admin
```

Submit your signature to `/claim` and get the flag.

## Start

Open:

```text
http://127.0.0.1:3000/start
```

You receive:

- curve: secp256k1
- public key
- message1, z1, r1, s1
- message2, z2, r2, s2

## Hint

Check whether:

```text
r1 == r2
```

If yes, the nonce `k` was reused.

Use:

```text
k = (z1 - z2) * inverse(s1 - s2, n) mod n
d = (s1*k - z1) * inverse(r, n) mod n
```

Then sign `role=admin` and submit:

```text
/claim?message=role%3Dadmin&r=<hex>&s=<hex>
```
