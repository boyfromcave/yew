# What YEW trusts

_The trust statement of the client contract (lightwalletd plan §5, rule 7; wallet plan §3.5,
§4). Shown once at onboarding and from Settings. The app's copy is `app/lib/trust_text.dart`;
`scripts/check-trust-text.sh` fails when the two differ._

YEW is a transparent-only wallet. Everything it does is public on the Ycash chain: your
addresses, your balances and every transaction can be seen by anyone. It holds no shielded
funds and never will.

Your keys never leave this device. The seed is kept in the phone's secure keystore, and every
signature is made in the wallet's own core. No server can spend your YEC or your YED.

For what it knows about the chain, YEW trusts one light-client server: the one named in
Settings. That server tells the wallet which coins exist, which of them are YED, the current
price, and whether a transaction it is about to send is sound. A dishonest server cannot take
your funds, but it can lie about them: it can hide a payment, show a balance that is not there,
or refuse to relay a transaction. If the server offers no Yellowback service, YED is hidden
until you connect to one that does.

Before any YED leaves the wallet, the transaction is checked twice: once here, against the
wallet's own record of which coins are YED, and once by the server's node, which must answer
that the transaction is valid, burns nothing and would be accepted. If either check fails,
nothing is sent. There is no way to skip this.

Use a server you trust, over TLS. On mainnet YEW refuses a connection without it.
