package me.flashapp.cashu.cardsim;

/**
 * The applet refused a step of a fixture. The fixture was validated before
 * the first APDU, so this is a card-state refusal (a PIN already set, a full
 * card), not a malformed request: the HTTP layer answers 409, and
 * {@code /state} reports the step and status word as {@code fixtureError}
 * until the next {@code /reset} or {@code /fixture}.
 */
final class FixtureException extends Exception {

    final String step;
    final int sw;

    FixtureException(String step, int sw) {
        super(step + " answered " + Hex.sw(sw));
        this.step = step;
        this.sw = sw;
    }
}
