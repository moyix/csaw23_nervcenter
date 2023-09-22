# Bitwise Overflow

Do we need to have some way to let the client make a bunch of connections without select being called? Each time after select() is called we zero the set (fine since FD_ZERO doesn't overflow) and then use FD_SET to re-add them to the set, which sets the corresponding bit to 1. So during setup we will overflow and set the target data to 0xFF...

Maybe using exceptfds helps here? If we don't handle the OOB data, then it will just get reset to the outstanding bit pattern every time, so it will flip between 0xFF and the bit pattern the client sets.

Yes! If the client never sends non-OOB data and the server never processes the OOB data then select sets readfds to all 0s and we can put whatever we want in exceptfds by sending OOBs.

# Questions

- Does the kernel actually write beyond FD_SETSIZE? YES
- How to get key in a overflowable format? Maybe just copy N into a fixed-size buffer after generating it?
- Control MSB or LSB?
    - Need to do empirical tests: if we try (say) all 2^5 possible 5-bit overflows, how many are factorable in 30 minutes?
    - Regen key every time they connect?
- Would elliptic curve signatures work better?
- Rowhammer paper also has attack on DH key exchange, hmm...

# RSA bit fault

For a 1024-bit RSA key, it seems like ~14% of the 7-bit patterns (19/128) result in a key that can be factored very quickly (less than a minute).

Idea from Tommaso Gagliardoni of Kudelski Security: instead of allowing most/least significant bits of N itself to be modified, instead have the exploit let you *extend* the key by a few bytes in the MSB. From email:

> I hadn't thought of the idea of adding MSBs, that could be very interesting! And potentially doable in a fairly "natural" way, by letting them corrupt not the modulus itself, but a 32-bit length field placed before the modulus (this format is in fact what's already used by the mpint data type in the SSH RFC, so it would be unremarkable). This would let them extend the key by a few bytes; the MSBs would be arbitrary data sitting in adjacent memory but I could arrange to have it be something random like a nonce or IV. Thanks for the idea!

If the key format is little endian and we have:

```
[fdset][keylength][keybytes][otherdata]
```

Then overflowing by a tiny bit (maybe only 1-2 bits) allows you to change the length of the key. If we choose the key size carefully so that the length's LSB starts out as zero then corruption can only increase the key length, causing the first couple bytes of `otherdata` to become part of the key. Very nice.


# Aesthetics

Scenario is a terminal interface to the [Magi supercomputers from Evangelion](https://evangelion.fandom.com/wiki/Magi). When you connect, it generates a public/private key pair and tells you that the private key will be given to you **out of band**; consult [Dr. Akagi](https://evangelion.fandom.com/wiki/Ritsuko_Akagi) for details (this part is a lie, but the phrase "out of band" is a hint). Aesthetics will be xterm-256color compatible screenshots from the show (what terminal width?):

* NERV logo on login
* Screenshot of MAGI interface
* Flag: happy group scene with flag text embedded
* Failed auth attempt: Asuka "pathetic"

UI is menu driven ()