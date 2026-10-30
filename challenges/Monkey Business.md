# Monkey Business — Day 27

## Single Solve — confirmed complete

- Route: `warmups-day-27`.
- Attempt: `ba771ee7-57b4-4125-9126-af3defa4d974`; untimed single solve.
- Assigned artifact: `blob.txt`, 33,929 bytes; SHA-256 `5b3672622adc74dcf7372ffe35803503dc960b64532f112f943c03eba44fedef`. It was downloaded through the authenticated Game Master artifact operation, transferred byte-for-byte to REMnux, and the local hash matched the assignment.
- The blob consists of Ook! tokens. Static decoding mapped `Ook. Ook.` to increment, `Ook! Ook!` to decrement, and `Ook! Ook.` to output, then interpreted the resulting single-cell byte stream. The 3,393 operations emitted 108 bytes of readable text.
- The final non-empty decoded line instructed submission of `hearty-castle-fern-71`. Submitted under answer ID `message`; the Game Master returned `CORRECT` with flag `3640d2283c2759710d37109d5d5153e9`. Personal status confirmed `CORRECT` and accepted `message`; completed by Jinzo.

## Time Trial — confirmed complete

- Route: `warmups-day-27/time_trial`.
- Attempt: `c912fdab-9247-4174-b29b-f0a4fe279658`; the route supports timed play, but this run used the default untimed scored mode (`run_for_time: false`), with no deadline.
- Assigned artifact: `blob.txt`, 34,089 bytes; SHA-256 `ee642e580e0d90383a07cea55988a2b7765da834460a668aa63dacb74c97f969`. The downloaded bytes were hash-checked and transferred to REMnux for static decoding.
- Interpreting the Ook! operations emitted 108 bytes. The final non-empty line instructed submission of `jaunty-cactus-ridge-14`.
- Submitted under `message`; Game Master returned `CORRECT` with flag `7871e2aa9778f5aa63c24a1ce206be57`. Personal status confirmed `CORRECT` and accepted `message`; completed by Jinzo.

## Mastery — confirmed complete

- Route: `warmups-day-27/mastery`.
- Attempt: `0e7b3783-4244-4721-8d40-bb1393e577d0`; untimed scored mode (`run_for_time: false`), no deadline. The assignment contained 133 sets and exact answer IDs `set1.message` through `set133.message`.
- Assigned artifact: `warmups-day-27-mastery.zip`, 356,764 bytes; SHA-256 `c104be83f8649c95154a88998555c0a4f1b485167af95f108dc0b695a3590cd6`. Downloaded through the authenticated Game Master operation, transferred to REMnux, hash-checked, and validated with `unzip -t`. It contains `blob-01.txt` through `blob-133.txt`.
- Static analysis decoded each blob's 27 tagged lines. The final phrase spans UTF-16LE/BE, gzip/Base64, zlib/Base64, ASCII85, run-length fields, Unicode code points, Brainfuck, and Ook!/Brainfuck. The `Master: ` marker frames the required slug. For example, `blob-01.txt` decodes to `Master: tidy-valley-glade-20`.
- Recovered all 133 slugs from the assigned files and submitted them together using their matching `setN.message` answer IDs. Game Master returned `CORRECT` with flag `cf96a1ad7c777cc8b7c366c043ab7401`; a subsequent personal status check also returned `CORRECT`, completed by Jinzo.
