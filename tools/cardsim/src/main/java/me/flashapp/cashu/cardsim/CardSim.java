package me.flashapp.cashu.cardsim;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

/**
 * cardsim: the real CashuApplet, protocol 2.0, in jCardSim, served over loopback HTTP.
 *
 * <pre>
 *   java -jar tools/cardsim/target/cardsim.jar [--port 9876]
 *   tools/cardsim/cardsim.sh [--port 9876]            # from source, via Maven
 * </pre>
 *
 * Binds 127.0.0.1 only. A port already in use is an error (exit 2), never a
 * reason to pick another: a loader that reaches a stale bridge from an
 * earlier run would be talking to a card holding that run's state. Android
 * reaches the bridge through {@code adb reverse tcp:9876 tcp:9876}.
 *
 * <p>This is the contract flash-pos and flash-mobile pin by {@code CASHU_JAVACARD_REF}:
 * the four routes below, their bodies, and client.cjs.
 *
 * <h2>API</h2>
 *
 * All bodies are JSON. Hex is case-insensitive in, upper case out for APDU
 * fields and lower case for the slot fields of {@code /state}.
 *
 * <dl>
 *   <dt>{@code POST /apdu}  {"hex": "00A404000BF043415348554341524401"}</dt>
 *   <dd>{@code 200 {"hex": "02009000", "sw": "9000"}} — the applet's answer,
 *       data‖SW. A non-9000 status word is still a 200: the transport worked,
 *       the card refused. 400 for bad JSON or bad hex. A SELECT by the package
 *       AID alone reaches the opener, as on a chip ({@code "9000"}, no version;
 *       SimCard's class comment, DECISIONS D25). <b>Never retried</b> by
 *       this server or by client.cjs: a replayed LOAD_PROOF burns a slot, and a
 *       replayed SPEND_ALL_SIGN of a payment already signed answers 6985 (the
 *       signature is had again with SPEND_ALL_AGAIN).</dd>
 *
 *   <dt>{@code POST /reset}</dt>
 *   <dd>A brand-new card: fresh simulator, the opener, the card's applet and
 *       the NFC tag installed, SELECT, {@code generation + 1}. Answers
 *       {@code /state}. <b>The key does not change</b>: jCardSim draws every
 *       keypair from an unseeded generator, so each install yields the same
 *       pubkey. Proofs minted to it in an earlier run are already spent at the
 *       mint if that run redeemed them. Loaders mint per run, after reading
 *       {@code pubkey} from {@code /state}.</dd>
 *
 *   <dt>{@code POST /fixture}  {pin?, mint?, refundKey?, owner?, ownerKey?, anchor?, headers?, proofs?, spentSlots?, limits?, blockedPin?}</dt>
 *   <dd>Additive on the current card (so: {@code /reset}, read
 *       {@code /state.pubkey}, mint format-4 SIG_ALL pieces locked to it, then
 *       {@code /fixture}). Fully validated against the card as it is before
 *       the first APDU — 400 {@code {"error"}} with the card untouched,
 *       including for the 0.x keys {@code puk} and {@code appletVersion}. A step
 *       the applet refuses answers 409
 *       {@code {"error": "<step>", "sw": "6985", "state": {...}}} and
 *       {@code /state.fixtureError} keeps the step until the next fixture or
 *       reset. On success, answers {@code /state}. Ends with a SELECT, so the
 *       app's first command finds a fresh session. {@code owner: true} sets the
 *       deterministic TEST owner key (OwnerKey.TEST, the same as cardctl's and
 *       client.cjs's), which the bridge then signs the owner's proofs with for
 *       {@code limits} and for loading. {@code spentSlots} are spent on the
 *       <i>card</i> only, by a payment of the piece with no outputs; the mint
 *       still holds those pieces live. See Fixture.java for the schema and
 *       SimCard.applyFixture for the order.</dd>
 *
 *   <dt>{@code GET /state}</dt>
 *   <dd>{@code {generation, deterministicKey: true, version, pubkey, balance,
 *       pinState, tries, locked, hasOwner, ownerKey?, testOwner, recordSet,
 *       mint?, now, windowStart, spentToday, dailyLimit, allowance, nopinSpent,
 *       rolls, rollBudget, allowanceArmed, lastHeader, counts: {unspent, spent,
 *       empty}, slots: [{slot, status, keysetId?, amount?, nonce?, C?, date?,
 *       dleq?: {e, s, r}}] (128 of them), fixtureError?: {step, sw}}}, read
 *       through commands that need no PIN and change nothing, without touching
 *       the session. {@code generation} moves on every reset and fixture, so a
 *       loader can tell a card it set up from one another run left behind.</dd>
 * </dl>
 *
 * Unknown path: 404. Wrong method: 405. Anything the server did not expect:
 * 500 {@code {"error"}} — the card is kept, nothing is retried.
 *
 * <h2>Sessions</h2>
 *
 * SELECT starts a session. The applet's PIN-verified flag, the owner's nonce
 * and the owner's load grant are CLEAR_ON_DESELECT transients, so a re-SELECT
 * drops them the way a new NFC tap does; the fake transport sends SELECT on
 * every tap and there is no "tap" endpoint. {@code /state} sends no SELECT while
 * the card's applet is selected; with another instance selected (the opener, by
 * the package AID) it selects the card's applet for its reads and the app's
 * instance again after (SimCard's class comment).
 *
 * <h2>The other bridge</h2>
 *
 * Foxy's fork also has {@code tools/cardsim/run.sh}: the same applet behind a
 * line protocol on port 47431 ({@code applet/src/test/java/.../CardServer.java}),
 * for Foxy's iOS Simulator build, with {@code ctl.sh} to take the card off the
 * reader. That is Foxy's wallet's transport, kept as it is; this HTTP bridge is
 * the one the Flash apps and the CI pin.
 *
 * <h2>Threads</h2>
 *
 * One handler thread. jCardSim keeps its runtime in a ThreadLocal, so the
 * simulator is constructed on that thread, inside {@link #start(int)}, and
 * every APDU, reset and fixture runs there. A card that cannot be built fails
 * {@code start()} before "listening" is ever printed, rather than answering 500
 * to every request. Concurrent requests are served one at a time.
 */
public final class CardSim {

    static final int DEFAULT_PORT = 9876;
    private static final Gson GSON = new Gson();

    private SimCard card;
    private final Supplier<SimCard> cardFactory;
    private final HttpServer server;
    private final ExecutorService executor;

    private CardSim(HttpServer server, ExecutorService executor, Supplier<SimCard> cardFactory) {
        this.server = server;
        this.executor = executor;
        this.cardFactory = cardFactory;
    }

    /**
     * The bound server with its card built; port 0 picks a free one (tests).
     * Throws BindException when the port is taken, and IllegalStateException
     * (the server stopped, the port released) when the card cannot be built.
     */
    public static CardSim start(int port) throws IOException {
        return start(port, SimCard::new);
    }

    /** {@link #start(int)} with the card's constructor swapped (tests). */
    static CardSim start(int port, Supplier<SimCard> cardFactory) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "cardsim-card");
            t.setDaemon(false);
            return t;
        });
        server.setExecutor(executor);
        CardSim cs = new CardSim(server, executor, cardFactory);
        server.createContext("/", cs::handle);
        server.start();
        // Build the card now, on the card thread, so a construction failure
        // surfaces here instead of as a 500 on the first request.
        try {
            executor.submit(cs::card).get();
        } catch (ExecutionException e) {
            cs.stop();
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new IllegalStateException("could not build the card: " + cause, cause);
        } catch (InterruptedException e) {
            cs.stop();
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while building the card", e);
        }
        return cs;
    }

    public int port() {
        return server.getAddress().getPort();
    }

    public void stop() {
        server.stop(0);
        executor.shutdownNow();
    }

    private SimCard card() {
        if (card == null) card = cardFactory.get();
        return card;
    }

    private void handle(HttpExchange ex) throws IOException {
        try {
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            switch (path) {
                case "/apdu":
                    if (!"POST".equals(method)) { methodNotAllowed(ex, "POST"); return; }
                    handleApdu(ex);
                    return;
                case "/reset":
                    if (!"POST".equals(method)) { methodNotAllowed(ex, "POST"); return; }
                    card().reset();
                    respond(ex, 200, card().state());
                    return;
                case "/fixture":
                    if (!"POST".equals(method)) { methodNotAllowed(ex, "POST"); return; }
                    handleFixture(ex);
                    return;
                case "/state":
                    if (!"GET".equals(method)) { methodNotAllowed(ex, "GET"); return; }
                    respond(ex, 200, card().state());
                    return;
                default:
                    respond(ex, 404, error("no such route: " + path));
            }
        } catch (IllegalArgumentException | JsonParseException e) {
            respond(ex, 400, error(e.getMessage()));
        } catch (Throwable t) {
            respond(ex, 500, error(t.getClass().getSimpleName() + ": " + t.getMessage()));
        }
    }

    private void handleApdu(HttpExchange ex) throws IOException {
        JsonObject body = object(body(ex));
        JsonElement hex = body.get("hex");
        if (hex == null || !hex.isJsonPrimitive() || !hex.getAsJsonPrimitive().isString()) {
            throw new IllegalArgumentException("body must be {\"hex\": \"<apdu>\"}");
        }
        byte[] resp = card().transmit(Hex.parse(hex.getAsString()));
        JsonObject out = new JsonObject();
        out.addProperty("hex", Hex.format(resp));
        out.addProperty("sw", Hex.sw(SimCard.sw(resp)));
        respond(ex, 200, out);
    }

    private void handleFixture(HttpExchange ex) throws IOException {
        SimCard c = card();
        Fixture f = Fixture.parse(body(ex), c.context());
        try {
            c.applyFixture(f);
        } catch (FixtureException e) {
            JsonObject out = new JsonObject();
            out.addProperty("error", e.step);
            out.addProperty("sw", Hex.sw(e.sw));
            out.add("state", c.state());
            respond(ex, 409, out);
            return;
        }
        respond(ex, 200, c.state());
    }

    private static JsonObject object(String body) {
        JsonElement e = JsonParser.parseString(body.isEmpty() ? "null" : body);
        if (e == null || !e.isJsonObject()) throw new IllegalArgumentException("body must be a JSON object");
        return e.getAsJsonObject();
    }

    private static String body(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static JsonObject error(String message) {
        JsonObject o = new JsonObject();
        o.addProperty("error", message == null ? "error" : message);
        return o;
    }

    private static void methodNotAllowed(HttpExchange ex, String allow) throws IOException {
        ex.getResponseHeaders().set("Allow", allow);
        respond(ex, 405, error("method not allowed; use " + allow));
    }

    private static void respond(HttpExchange ex, int status, JsonElement body) throws IOException {
        byte[] bytes = GSON.toJson(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    public static void main(String[] args) {
        int port = DEFAULT_PORT;
        for (int i = 0; i < args.length; i++) {
            if ("--port".equals(args[i]) && i + 1 < args.length) {
                try {
                    port = Integer.parseInt(args[++i]);
                } catch (NumberFormatException e) {
                    System.err.println("cardsim: --port needs a number, got " + args[i]);
                    System.exit(1);
                }
            } else if ("--help".equals(args[i]) || "-h".equals(args[i])) {
                System.out.println("usage: cardsim [--port N]   (default " + DEFAULT_PORT + ", loopback only)");
                return;
            } else {
                System.err.println("cardsim: unknown argument " + args[i]);
                System.exit(1);
            }
        }
        CardSim cs;
        try {
            cs = start(port);
        } catch (BindException e) {
            System.err.println("cardsim: port " + port + " in use: a stale cardsim is running. "
                + "Stop it rather than picking another port; a loader must never reach a card from an earlier run.");
            System.exit(2);
            return;
        } catch (IOException e) {
            System.err.println("cardsim: could not listen on 127.0.0.1:" + port + ": " + e.getMessage());
            System.exit(1);
            return;
        } catch (IllegalStateException e) {
            // a SELECT that did not answer a 2.x version after install
            System.err.println("cardsim: could not build the card: " + e.getMessage());
            System.exit(1);
            return;
        }
        System.out.println("cardsim listening on http://127.0.0.1:" + cs.port()
            + " (jCardSim; the card key is deterministic: mint per run)");
        Runtime.getRuntime().addShutdownHook(new Thread(cs::stop, "cardsim-shutdown"));
        try {
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}
