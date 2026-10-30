# Read the Rules — Single Solve write-up

This records the Day 1 **Read the Rules** Single Solve (`read-the-rules`). The attempt was untimed and had no downloadable artifact.

## Assignment and analysis

The Game Master instructed me to inspect `https://ctf.huntress.com/rules` and submit the flag hidden in the page HTML. The visible page did not show a flag. I inspected the rendered document’s raw HTML and found an HTML comment containing `flag{bf61aced6e7f9335385a70f33b20d188}`.

## Submission result

The first submission omitted the `flag{}` wrapper and was rejected. Submitting the exact complete value from the comment under the sole answer ID `flag` returned `CORRECT`; the follow-up status check also returned `CORRECT`.

Completion flag: `flag{bf61aced6e7f9335385a70f33b20d188}`
