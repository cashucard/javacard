<a id="flashcard-the-screens-as-they-are-built"></a>

# Foxy Flashcard screens (historical)

What each screen is for, what is on it, and its states, in the wallet as it
stands (the wallet repository, getfoxy/iOS, https://github.com/getfoxy/iOS:
`build/app/26f-flashcard.js` and the FLASHCARD block of `build/markup.html`).
This was the designer's brief before the screens existed; it now describes what
was made, and where the two differ the app is right. Pictures of every screen:
the render snapshots (`tests/snapshots/render`, the views named `flashcard…`,
`card: …`, `stage: …`, `amount, … a card`, `switchMint, …`, `fcMoveConfirm, …`).

Rules the screens keep to:
- **Nothing new where the app already has it.** Amounts are typed on the
  app's own SET AMOUNT screen, dollars first and sats under them. The PIN pad
  is the lock screen's pad. Results are the app's own cards. The card's own
  screen is home's layout, element for element.
- **A way back at the top left, never CANCEL at the bottom.** The button that
  commits says what it does and how much (`PAY $0.43`, `ADD $2.00 TO CARD`),
  and is grey until it can be pressed.
- **The card tap sheet is Apple's.** It slides up whenever the phone is
  looking for a card. One line of text on it is ours and changes during a
  tap. Our own screen sits behind it and says the same.
- **Cards are cash for now.** A card that can be taken back by the phone that
  loaded it is built and switched off (`FC_RECOVERABLE`); what belongs to it
  is listed in E and is on no screen.
- **The word is daily limit.** The screens call what the card keeps the daily
  limit, and its row CHANGE LIMIT. The card's screen shows it, what is left of
  it today and when the day turns.
- **The PIN is optional (software 1.16).** A card may be set up with no PIN, and
  then it pays without one. A card that has a PIN has a third figure beside the
  daily limit, the NO PIN LIMIT: how much it will pay in a day without the PIN
  being typed. Over it the till asks for the PIN, for the whole payment. A card
  with no PIN has no such figure, and no screen mentions one. A card of software
  before 1.16 always asks for its PIN, and keeps today's flow (A2 first).

## A. Paying by card (the receiver's phone)

### A1. Receive invoice screen (the app's own)
- A **CARD** button beside TAP.
- On a card of software 1.16 the button goes straight to the sheet and the tap,
  with no PIN pad first (A3): the card says whether it needs the PIN. A card of
  an earlier software goes to A2 first, because it always asks for the PIN and a
  tap before it would be wasted.

### A2. Card PIN
The payer types their card's PIN on the receiver's phone.
- A back button at the top left
- Title `CARD PIN`; under it `To pay $0.43 (₿500). The card's owner types its PIN here.`
- PIN dots, 4 to 8; the key pad
- After a wrong PIN, a red line: `Wrong PIN. 2 tries left.`
- (1.16) Also the pad that follows a tap which found the card needs the PIN, with
  TAP AGAIN where the PAY button is
- The button: `PAY $0.43`, grey until four digits are in

### A3. Tapping (behind Apple's sheet, and after it)
On a card of software 1.16 the tap comes first. The card is read; if it has no
PIN, or the amount is within its no-PIN allowance (what is left of it today), the
payment goes in that tap, and the PIN is never asked. Otherwise the sheet ends
saying `Enter the card's PIN`, the PIN pad of A2 comes up, and TAP AGAIN pays with
the PIN, sealed as ever. The card's own answer is the truth (`6A94` at the
signature, which closes the sheet the same way), and what the phone read first only
saves a signature that would be refused. Nothing was taken either way.

One screen, with the amount on it throughout:
- `HOLD THE CARD TO THE TOP OF THE PHONE` (CANCEL only here)
- `READING THE CARD`
- `KEEP THE CARD THERE` (the card signs, then the mint is asked: a few seconds)
- `PUTTING CHANGE BACK ON THE CARD`
- `WRITING TO THE CARD`
- `REMOVE THE CARD`

Under the heading a line says what the card is doing now, and the phone's own
sheet says the same: `Scanning. Hold still.` when the card is found, then
`Reading the card`, `Signing piece 3 of 9`, `Writing 2 of 4`, and last
`Done. Remove the card.` The piece is said before the card is asked for it, so the
line is up for as long as the card works on it. (The sheet's big title is the
system's and cannot change.)

### A4. Results
Each is one of the app's cards: a title, a line or two, one or two buttons.

| Result | Says |
|---|---|
| the paid confirmation | the usual one; the payment's entry is marked as a card's |
| WRONG PIN | the tries left, and that nothing was taken; TRY AGAIN |
| CARD BLOCKED | too many wrong PINs; the card can pay again when its owner sets a new PIN on it |
| NOT ENOUGH ON THE CARD | what it holds |
| OVER THE CARD'S DAILY LIMIT | the card holds enough, but what is left of today's limit cannot cover this payment. Says how much the card can still spend today and when its day turns. Said in plain words after the card is read and before its PIN is sent; nothing was taken |
| A DIFFERENT MINT | the card's mint and this phone's |
| NO CHANGE WHILE OFFLINE | this phone has no connection and cannot give change, and the card does not hold pieces that make exactly the price. Said before the PIN is sent; nothing was taken |
| TAKEN ON TRUST | this phone has no connection, so the mint was not asked: the card's pieces are kept and swapped in when it is online. Not paid until then. Asked first, with the HIGH RISK card (YOU ARE OFFLINE), CONTINUE or REJECT, before the PIN |
| ENTER THE CARD'S PIN | (1.16) the card has a PIN and the amount is over its no-PIN allowance, by what the phone read or by the card's own `6A94`. The PIN pad of A2 follows; TAP AGAIN pays. Nothing was taken |
| NO MONEY ON THIS CARD | nothing loaded (a card with no PIN, 1.16, may be loaded and pays without one) |
| NOT A FOXY CARD | it could not be read, or is another kind |
| NO CARD READER | this phone, or this build, cannot read cards |
| THE CARD LEFT TOO SOON | nothing was paid; what the card signed for goes back on it |
| CHECKING, then STILL CHECKING | the card has signed and the mint has not answered; ends as paid or as money to go back on the card |
| TAP THE CARD AGAIN | the payment is made and change is waiting to go back on the card; TAP CARD, LATER |

TAP THE CARD AGAIN is the one that outlives the screen: see D2.

## B. Menu › FLASHCARD (the holder's own phone)

### B1. Menu
- **FLASHCARD**. It goes straight to Apple's sheet: there is no screen to
  press TAP CARD on first.

### B2. The card's screen
Home's layout, so the two read as one design:
- **Top left:** the round history button. It opens this card's history (B8).
  Hidden for a card that is not set up.
- **Top right:** a round button with a cross. It closes the screen.
- **Between them:** `FLASHCARD`, and under it how fresh the mint's word is:
  `Verifying…`, `Verified Just Now`, on a phone with no connection
  `Verified 2 Hours Ago` (the last time this phone had the mint's word on the
  same pieces), or `Not Verified`.
- **The card**, drawn in its design (`docs/CARD-DESIGNS.md`; FL1 today). One
  line on its face, bottom left, only for what is not ordinary: `NO PIN YET`,
  `NOT FINISHED`, `LOCKED`, `BLOCKED`, or `THE MINT SAYS ₿1,024 IS ALREADY
  SPENT`.
- **CARD BALANCE**: home's panel and home's pill. The mint's tile and name on
  the left (not a button); the balance on the right, dollars over sats.
  Tapping the balance opens this card's history.
- **The daily limit**, under the balance: `DAILY LIMIT` and its amount, or
  `NO LIMIT`; with a limit, `LEFT TODAY` and its amount, and `THE DAY TURNS
  AT` a time. Dollars first, as the balance is. (1.16) On a card that has a PIN
  and a no-PIN limit, the limit line gains it: `NO PIN UP TO $10`, with what is
  left of it today.
- A line in the warning colour when money is waiting to go onto a card
  (`₿500 is waiting to go onto this card. Press here, then tap it.`).
- **ADD FUNDS** and **WITHDRAW** where home has RECEIVE and SEND;
  **CHANGE PIN** and **CHANGE LIMIT** where it has SCAN and PASTE. On a card with
  no PIN (1.16) CHANGE PIN reads **ADD PIN** (B6).
- The connection's banner at the foot, as on home.

A new card has, in place of the pill and the buttons, one line (`This card is
new. Give it a PIN to put money on it.`; since 1.16 the PIN may be left out, B3)
and **SET UP THIS CARD**. A blocked
card has the pill and a red line. On its owner's phone the line says that this
phone can unblock the card by giving it a new PIN, and there is one button,
**UNBLOCK**, which is CHANGE PIN (B6); on any other phone the line says that
only the phone that owns the card can unblock it, and there are no buttons.

How many pieces the card holds, and what happens if it is lost, are not shown
on this screen.

### B3. Setting up a new card
- `CHOOSE A PIN` (`Four to eight digits. The card asks for it every time it
  pays.`), then `TYPE IT AGAIN`; NEXT under each. (1.16) Under the pad on
  CHOOSE A PIN, a second button, **NO PIN**: the card is set up with none, and the
  next step is the tap, as it is with a PIN. The warning that a card with no PIN
  is cash to whoever holds it is not here; it is said where a PIN is offered
  later (B6, ADD PIN)
- The notice, titled `SET UP THIS CARD`: `This phone can reset this card's PIN
  and limit. Whoever holds the card and this phone's seed phrase holds its
  money.` with the buttons CONTINUE and CANCEL. It is the one place that says
  what making this phone the owner means. For a holder with no phone of their
  own, the owner is the friend's phone that sets the card up
- No limit is asked for and none is suggested: a new card has none. A limit is
  set later from CHANGE LIMIT (B7)
- A tap, which writes the card's PIN (none, with NO PIN), its record and, last, its
  owner key. The owner goes in last so that no step needs a proof: a set-up cut
  off anywhere is finished by the next set-up tap
- `THE CARD IS READY`: that it is cash, that whoever has the card and its PIN
  has the money, and that if the card is lost the money on it is gone. ADD
  FUNDS, LATER

### B4. Add funds
- The app's SET AMOUNT screen, NEXT
- On the owner's phone no PIN is asked: the card is given the owner's proof
  and lets the money in for that tap. On any other phone, `CARD PIN`, the button
  `ADD $2.00 TO CARD`
- Putting money on a card does not touch its limit
- A tap; `GETTING IT READY`, then the states of A3
- `ON THE CARD` with the new balance; or the card left early and the money
  waits for it (the line of B2); WRONG PIN; THE CARD IS FULL
- What goes on is cut into as few pieces as it can be, never more than sixteen in
  a load. An amount that needs more is rounded up a few sats, and `ON THE CARD`
  says by how much
- A card at another mint than this phone's: `A DIFFERENT MINT`. If it holds
  anything: "You need to withdraw all funds on the card before you can switch
  mints." and CLOSE. If it holds nothing, on its owner's phone: `SWITCH TO <MINT>`,
  which goes straight to SET AMOUNT; the card is told its new mint with the owner's
  proof, in the same tap that writes the funds (its PIN, owner, limit and clock
  stay as they are), and `ON THE CARD` says the card is now at the new mint. On any
  other phone, the card says only the phone that set it up can switch it

### B5. Withdraw
- SET AMOUNT, with `ALL OF IT ($1.31)` under NEXT
- `ENTER PIN TO WITHDRAW`; a tap
- `IN YOUR WALLET`; WRONG PIN; CHECKING
- The limit is no obstacle to the owner's phone: in the same tap it lifts the
  limit with the owner's proof, spends (the PIN is still asked), and puts the
  limit back with the owner's proof, even when the spending fails part way. If
  the card leaves before the limit can be put back, the phone has written the
  old limit down first and puts it back at the next tap. A phone that does not
  hold the card's seed phrase cannot lift the limit, and says so in plain
  words. Renewing and taking everything off a card work the same way.

### B6. Change PIN, and unblock
- On a card with no PIN (1.16) the row reads **ADD PIN**. Its first screen says,
  in one line, that a card with no PIN is cash to whoever holds it. Then
  `CHOOSE A PIN` and `TYPE IT AGAIN`, and one tap: the owner's grant, then the PIN,
  sealed. The toast: `PIN added. Every payment asks for it until you set a no-PIN
  limit.` The card's no-PIN limit is nothing until then (B7a)
- Two pads in turn: `NEW PIN`, then `NEW PIN AGAIN`; a tap. No old PIN is asked:
  the owner's phone does not know it, and the card takes the owner's proof in
  its place
- `PIN CHANGED`
- A blocked card, on its owner's phone, has the button **UNBLOCK** (B2). It is
  the same pads and the same tap, and ends at `CARD UNBLOCKED`
- On a phone that does not hold the card's seed phrase the change fails, and
  the screen says so in plain words (`NOT THIS PHONE'S CARD`)

### B7. Change limit
The row is CHANGE LIMIT. Three steps, then a tap.

1. **A full-screen warning.** Title `SET DAILY LIMIT`. Body, three paragraphs:
   - `A daily limit is the most this card will spend in one day. It starts again by itself each day.`
   - `Only this phone, or a phone restored from its seed phrase, can change or remove the limit.`
   - `If you lose the seed phrase for this Foxy app, the PIN and the limit on this card can never be changed.`

   Then `Do you wish to continue?` with the buttons CONTINUE and CANCEL.
2. **The app's SET AMOUNT screen**, dollars first and sats under them, asking
   `What would you like the daily limit to be?`; NEXT, and under it **NO LIMIT**,
   which is the way to remove a limit.
3. **A confirmation**, after NEXT, titled `CONFIRMATION`:
   - `YOU ARE APPLYING A DAILY LIMIT OF:` and the amount chosen, dollars first
   - `This card will spend no more than this in one day. The limit starts again by itself each day. Only this phone, or a phone restored from its seed phrase, can change or remove it.`

   with the buttons CONFIRM and CANCEL. After NO LIMIT the confirmation says
   `YOU ARE REMOVING THIS CARD'S DAILY LIMIT.` over `NO LIMIT`, and
   `It will be able to spend everything on it.`

Then one tap writes it to the card with the owner's proof; no PIN is asked.
Set-up (B3) does not ask for a limit and does not suggest one: a new card has
none. No screen suggests a figure.

What the card does behind these words (specification 5.7): it spends no more
than the limit in a day, and starts the day again by itself. Its day is counted
by the Bitcoin block headers it is shown, and not by anyone's word, so a
terminal that has been handed the PIN can take one day's limit per visit, and no
more, honest or not (up to two across the edge of a day). The card starts a new
day when it is shown a block a day on from the day's start, which the phone does
at the tap when the card is behind; a card that is shown none does not start it,
and the time on the card's screen is the earliest it can. No screen says more of
the limit than that. If the seed phrase is lost, the PIN and the limit can never
be changed, and a blocked card can never be unblocked. A phone that does not hold
the card's seed phrase cannot change the limit, and says so.

### B7a. No PIN limit (1.16)
Shown in CHANGE LIMIT, as a third button, **NO PIN LIMIT**, in the pill style of
DAILY LIMIT, and only on a card that has a PIN. Its three steps are the daily
limit's:

1. **A warning**: what it is. `Your card pays up to this much a day without the PIN
   being typed. Over it, the PIN is asked for the whole payment. Only payments
   made without the PIN count.`
2. **The app's SET AMOUNT screen**, dollars first, with **NO LIMIT** under NEXT,
   which is 0: every payment asks for the PIN.
3. **A confirmation**, then a tap, which writes the three limits to the card with
   the owner's proof (the daily limit and the limit on one payment as they were).
   No PIN is asked.

The card's screen shows it in its limit line (B2). A card that has no PIN has no
such button. The dollars are re-pegged by the owner's phone, as the daily limit's
are, when the price moves.

### B8. A card's history
- The app's HISTORY screen, titled `CARD HISTORY`, with only the entries that
  name this card: money put on it, money taken off it, and payments taken
  from it on this phone. The wallet's running balance and its audit card are
  left off, and there is no button to clear it.
- A card keeps no list of its own. What it paid at somebody else's phone is
  not here.
- (1.16) The log screen, which reads the card's own account, says `no PIN` beside
  a tap in which a payment was made without the PIN, under the no-PIN limit.

### B9. Moving a card to another mint (built, with no button for now)
- The app's list of mints, titled `TO WHICH MINT?`, without the card's own
- The app's CONFIRMATION: where to, where from, about what arrives on the
  card, and the most the fee can be; `MOVE ₿2,000`
- `CARD PIN`, once; then two taps with the Lightning payment between them:
  the money comes off the card, crosses, and goes back on at the new mint
- `MOVED`; or the card was put away before its second tap and the money
  waits for it at the new mint; or `NOT MOVED`, with the money in this phone
- A card with nothing on it: its PIN and one tap, no confirmation
- It works whichever mint the phone is at, and puts the phone back after

## C. History (the app's own)
- Three kinds of entry in the existing row style: a payment taken from a
  card, money put on a card, money taken off one.
- A holder's own moves to and from their card are not announced a second
  time; a payment from a card is, like any other.

## D. Notices that live outside the card's screen

### D1. On the holder's phone
- Money made for a card and not yet on it: the line on the card's screen
  (B2). Not yet said on home.

### D2. On the receiver's phone
- Change waiting for a payer's card: on that payment's own entry, which says
  to tap the card. It stays until the card is tapped.

<a id="e-built-and-on-no-screen-while-cards-are-cash"></a>

## E. Implemented features outside the current screens

- Choosing how a lost card is treated when it is set up (`IF THE CARD IS LOST`)
- The screen before a card is tapped, with `CARDS YOU LOADED` under it
- Taking a lost card's money back after its date (`TAKE IT BACK?`, `BACK IN
  YOUR WALLET`, `NOTHING WAS LEFT ON IT`)
- Renewing a card in its last month, from a line on its screen (it lifts the
  limit and puts it back, as B5 does); `CARD NEEDS RENEWING` and `ITS DATE HAS PASSED` at
  a till
