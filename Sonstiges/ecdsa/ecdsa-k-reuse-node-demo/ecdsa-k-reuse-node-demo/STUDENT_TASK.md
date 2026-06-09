# Aufgabe: ECDSA Nonce Reuse

## Situation

Ein Signaturserver verwendet ECDSA auf `secp256k1`.

Öffne:

```text
http://127.0.0.1:3000/start
```

Du erhältst zwei Signaturen:

```text
message1, z1, r1, s1
message2, z2, r2, s2
```

## Ziel

Signiere diese Nachricht:

```text
role=admin&action=get_flag
```

und sende deine Signatur an:

```text
/claim?message=role%3Dadmin%26action%3Dget_flag&r=<r_hex>&s=<s_hex>
```

## Hinweise

1. Vergleiche `r1` und `r2`.
2. Wenn `r1 == r2`, wurde wahrscheinlich dieselbe Nonce `k` verwendet.
3. Für secp256k1 gilt die Kurvenordnung `n`, die im JSON unter `curveOrderN` steht.
4. Formeln:

```text
k = (z1 - z2) * (s1 - s2)^-1 mod n
```

```text
d = (s1*k - z1) * r^-1 mod n
```

5. Mit `d` kannst du eine gültige Signatur für die Admin-Nachricht erzeugen.
