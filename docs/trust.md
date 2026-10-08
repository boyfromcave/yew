# What YEW trusts

_The trust statement of the client contract (lightwalletd plan §5, rule 7; wallet plan §3.5,
§4). Shown once at onboarding and from Settings. The app's copy is `app/lib/trust_text.dart`;
`scripts/check-trust-text.sh` fails when the two differ, and on this branch (in-term claims) when
the paragraph opening "Your YEC is locked" is not the in-term promise of the node's generated spec
(§8.1; the workspace's in-term plan IT-8) verbatim._

YEW holds YEC in two ways. Private YEC sits in a shielded Ycash address (ys1…): the chain
hides who paid whom, how much, and any message. Public YEC and all YED sit in transparent
addresses: those addresses, their balances and every transaction can be seen by anyone on the
Ycash chain. YED, minting and every YED fee use public YEC only. Nothing moves between private
and public unless you send it yourself, and a payment from your private balance to a public
address shows its amount on the chain.

Your keys never leave this device. The seed is kept in the phone's secure keystore, and every
signature is made in the wallet's own core. No server can spend your YEC or your YED.

For what it knows about the chain, YEW trusts one light-client server: the one named in
Settings. That server tells the wallet which coins exist, which of them are YED, the current
price, and whether a transaction it is about to send is sound. A dishonest server cannot spend
your YEC or your YED, but it can lie about them: it can hide a payment, show a balance that is
not there, or refuse to relay a transaction. If the server offers no Yellowback service, YED is
hidden until you connect to one that does.

For your private balance the server sends blocks that the wallet scans on this phone, so the
scan does not tell the server which payments are yours. To read the messages of your private
payments, the wallet asks the server for those transactions, which does tell it they are
yours. The server also sees when you connect and every transaction you send, but not what a
private one contains. The files needed for private sending (52 MB) are downloaded once, from
the standard source ycashd uses or an address set in Settings, and kept only if they match
fingerprints built into YEW.

When you mint, redeem or claim, the wallet checks the server's terms against the network's
rules before you confirm: the lock and claim heights, the collateral the price calls for, the
enforcement fee and, on a redeem before the term ends, the early-redeem fee, each always the
rule's amount and never more, and on a claim the share returned to the vault's owner. It then
signs only what you confirmed: if the server's answer would lock more collateral, burn more YED
or pay you less, nothing is signed. What it cannot check is the fee's recipient: the server
chooses which eligible miner the fee goes to, or that none is due. Use a server you trust for
these operations.

Your YEC is locked for the term you choose. You can redeem at any time by paying back the YED
you minted; redeeming before the term ends also costs an early-redeem fee of 5 %, 2.5 % or 1 %
of your collateral for a short, medium or long term. If your collateral falls below 125 % of
your debt at the attested price, anyone may close your vault by paying your debt; you then
receive whatever collateral is worth more than 125 % of the debt — which, at the threshold, is
usually nothing. Before that happens, your wallet will warn you, and redeeming stops it.

In a year like the last, the calibration expects between 19 % and 50 % of vaults to be claimed
in term.

Before any YED leaves the wallet, the transaction is checked twice: once here, against the
wallet's own record of which coins are YED, and once by the server's node, which must answer
that the transaction is valid, burns nothing and would be accepted. If either check fails,
nothing is sent. There is no way to skip this.

Use a server you trust, over TLS. On mainnet YEW refuses a connection without it.
