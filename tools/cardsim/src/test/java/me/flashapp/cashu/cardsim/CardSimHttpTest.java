package me.flashapp.cashu.cardsim;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.BindException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class CardSimHttpTest {

    CardSim sim;
    HttpClient http;
    String base;

    @BeforeEach
    void start() throws IOException {
        sim = CardSim.start(0);
        base = "http://127.0.0.1:" + sim.port();
        http = HttpClient.newHttpClient();
    }

    @AfterEach
    void stop() {
        sim.stop();
    }

    HttpResponse<String> post(String path, String body) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + path))
            .POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
            HttpResponse.BodyHandlers.ofString());
    }

    static JsonObject json(HttpResponse<String> r) {
        return JsonParser.parseString(r.body()).getAsJsonObject();
    }

    @Test
    @DisplayName("POST /apdu round-trips a SELECT by the card's applet's whole AID, F0 CASHUCARD 01: 02 01")
    void apduRoundTrip() throws Exception {
        HttpResponse<String> r = post("/apdu", "{\"hex\":\"00A404000BF043415348554341524401\"}");
        assertEquals(200, r.statusCode());
        assertEquals("application/json", r.headers().firstValue("Content-Type").orElse(""));
        JsonObject o = json(r);
        assertEquals("02019000", o.get("hex").getAsString());
        assertEquals("9000", o.get("sw").getAsString());
    }

    @Test
    @DisplayName("POST /apdu with a SELECT by the package AID alone reaches the opener, as on the chip: 9000, no body, then 6D00")
    void packageAidReachesTheOpener() throws Exception {
        JsonObject o = json(post("/apdu", "{\"hex\":\"00A404000AF0434153485543415244\"}"));
        assertEquals("9000", o.get("hex").getAsString());
        assertEquals("9000", o.get("sw").getAsString());
        assertEquals("6D00", json(post("/apdu", "{\"hex\":\"B001020000\"}")).get("sw").getAsString());
        // GET /state still reads the card, and leaves the opener selected for the app
        HttpResponse<String> state = get("/state");
        assertEquals(200, state.statusCode(), state.body());
        assertEquals("2.1", json(state).get("version").getAsString());
        assertEquals("6D00", json(post("/apdu", "{\"hex\":\"B001020000\"}")).get("sw").getAsString());
        assertEquals("02019000", json(post("/apdu", "{\"hex\":\"00A404000BF043415348554341524401\"}")).get("hex").getAsString());
        assertEquals("9000", json(post("/apdu", "{\"hex\":\"B001020000\"}")).get("sw").getAsString());
    }

    @Test
    @DisplayName("the 0.x AID selects nothing over the bridge: a 200 carrying the refusal")
    void oldAidIsNotFound() throws Exception {
        HttpResponse<String> r = post("/apdu", "{\"hex\":\"00A4040007D2760000850102\"}");
        assertEquals(200, r.statusCode());
        String sw = json(r).get("sw").getAsString();
        assertTrue(sw.equals("6A82") || sw.equals("6999") || sw.equals("6E00"), sw);   // see OldCardTest.oldAidsAreNotFound
    }

    @Test
    @DisplayName("a card refusal is still a 200: the transport worked")
    void refusalIs200() throws Exception {
        HttpResponse<String> r = post("/apdu", "{\"hex\":\"B0 13 1F 00 52\"}"); // GET_PROOF of an empty slot
        assertEquals(200, r.statusCode());
        assertEquals("6A88", json(r).get("sw").getAsString());
        assertEquals("6A88", json(r).get("hex").getAsString());
    }

    @Test
    @DisplayName("bad hex, odd length, bad JSON, missing field, short APDU → 400")
    void badRequests() throws Exception {
        assertEquals(400, post("/apdu", "{\"hex\":\"zz\"}").statusCode());
        assertEquals(400, post("/apdu", "{\"hex\":\"B01\"}").statusCode());
        assertEquals(400, post("/apdu", "{\"hex\":\"B0\"}").statusCode());
        assertEquals(400, post("/apdu", "not json").statusCode());
        assertEquals(400, post("/apdu", "{}").statusCode());
        assertEquals(400, post("/apdu", "[]").statusCode());
        assertEquals(400, post("/apdu", "").statusCode());
        // jCardSim parses the C-APDU before the applet sees it: an Lc that
        // does not match the data is refused here, not answered 6700.
        HttpResponse<String> badLc = post("/apdu", "{\"hex\":\"B04000000531323334\"}");
        assertEquals(400, badLc.statusCode());
        assertTrue(json(badLc).get("error").getAsString().contains("Lc"), json(badLc).toString());
        assertEquals(400, post("/fixture", "{\"bogus\":1}").statusCode());
        assertEquals(400, post("/fixture", "{\"pin\":\"1\"}").statusCode());
        assertTrue(json(post("/fixture", "{\"bogus\":1}")).get("error").getAsString().contains("bogus"));
    }

    @Test
    @DisplayName("unknown route 404, GET on /apdu 405, POST on /state 405")
    void routing() throws Exception {
        assertEquals(404, get("/nope").statusCode());
        HttpResponse<String> r = get("/apdu");
        assertEquals(405, r.statusCode());
        assertEquals("POST", r.headers().firstValue("Allow").orElse(""));
        assertEquals(405, post("/state", "").statusCode());
        assertEquals(405, get("/reset").statusCode());
        assertEquals(405, get("/fixture").statusCode());
    }

    @Test
    @DisplayName("GET /state is the card document; POST /reset bumps the generation")
    void stateAndReset() throws Exception {
        JsonObject s = json(get("/state"));
        assertEquals(0, s.get("generation").getAsLong());
        assertEquals("2.1", s.get("version").getAsString());
        assertEquals(66, s.get("pubkey").getAsString().length());
        assertEquals(128, s.getAsJsonArray("slots").size());
        assertEquals(7, s.get("rollBudget").getAsInt());
        assertTrue(s.get("deterministicKey").getAsBoolean());

        HttpResponse<String> r = post("/reset", "");
        assertEquals(200, r.statusCode());
        assertEquals(1, json(r).get("generation").getAsLong());
        assertEquals(s.get("pubkey").getAsString(), json(r).get("pubkey").getAsString(), "deterministic key");
    }

    @Test
    @DisplayName("POST /fixture applies and answers state; a refused step answers 409 {error, sw, state}")
    void fixture() throws Exception {
        HttpResponse<String> ok = post("/fixture", "{\"pin\":\"1234\",\"mint\":\"http://m\",\"owner\":true,\"blockedPin\":true}");
        assertEquals(200, ok.statusCode());
        assertEquals(2, json(ok).get("pinState").getAsInt());
        assertTrue(json(ok).get("hasOwner").getAsBoolean());
        assertEquals(1, json(ok).get("generation").getAsLong());

        HttpResponse<String> refused = post("/fixture", "{\"pin\":\"5678\"}");
        assertEquals(409, refused.statusCode());
        JsonObject o = json(refused);
        assertEquals("VERIFY_PIN", o.get("error").getAsString());
        assertEquals("6983", o.get("sw").getAsString());
        JsonObject state = o.getAsJsonObject("state");
        assertEquals(2, state.get("generation").getAsLong());
        assertEquals("VERIFY_PIN", state.getAsJsonObject("fixtureError").get("step").getAsString());
        assertEquals("VERIFY_PIN", json(get("/state")).getAsJsonObject("fixtureError").get("step").getAsString());

        HttpResponse<String> after = post("/apdu", "{\"hex\":\"B018000000\"}");
        assertEquals("6982", json(after).get("sw").getAsString(), "the fixture's card is still blocked: no log without the PIN");
    }

    @Test
    @DisplayName("the 0.x fixture keys answer 400 by name, with the card untouched: puk and appletVersion")
    void oldFixtureKeysAre400() throws Exception {
        String before = get("/state").body();
        HttpResponse<String> puk = post("/fixture", "{\"puk\":\"12345678\"}");
        assertEquals(400, puk.statusCode());
        assertTrue(json(puk).get("error").getAsString().contains("no PUK"), puk.body());
        HttpResponse<String> version = post("/fixture", "{\"appletVersion\":\"0.4\"}");
        assertEquals(400, version.statusCode());
        assertTrue(json(version).get("error").getAsString().contains("version masks are gone"), version.body());
        assertEquals(before, get("/state").body(), "card untouched");
    }

    @Test
    @DisplayName("every new fixture field applies over HTTP: owner, mint, headers, limits with the budget, a piece with its mint's proof")
    void newFixtureFields() throws Exception {
        String header = SimCardTest.HEADERS.get(5);
        String proof = "{\"keysetId\":\"0059534ce0bfa19a\",\"amount\":8,\"nonce\":\"" + "ab".repeat(32)
            + "\",\"C\":\"02" + "11".repeat(32) + "\",\"dleq\":{\"e\":\"" + "01".repeat(32) + "\",\"s\":\"" + "02".repeat(32)
            + "\",\"r\":\"" + "03".repeat(32) + "\"}}";
        HttpResponse<String> r = post("/fixture", "{\"pin\":\"1234\",\"mint\":\"http://127.0.0.1:3338\",\"owner\":true,\"anchor\":\""
            + header + "\",\"proofs\":[" + proof + "],\"limits\":{\"day\":1000,\"allowance\":100,\"rollBudget\":5}}");
        assertEquals(200, r.statusCode(), r.body());
        JsonObject s = json(r);
        assertEquals(SimCardTest.TIMES.get(5).longValue(), s.get("now").getAsLong());
        assertEquals(1000, s.get("dailyLimit").getAsLong());
        assertEquals(100, s.get("allowance").getAsLong());
        assertEquals(5, s.get("rollBudget").getAsInt());
        assertTrue(s.get("testOwner").getAsBoolean());
        assertEquals("http://127.0.0.1:3338", s.get("mint").getAsString());
        assertEquals("01".repeat(32), s.getAsJsonArray("slots").get(0).getAsJsonObject().getAsJsonObject("dleq").get("e").getAsString());
    }

    @Test
    @DisplayName("concurrency: 16 threads x 50 GET_INFO all answer 9000 from the one card thread")
    void concurrency() throws Exception {
        int threads = 16, perThread = 50;
        CountDownLatch go = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        List<Throwable> failures = new ArrayList<>();
        List<Thread> pool = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            Thread th = new Thread(() -> {
                try {
                    HttpClient client = HttpClient.newHttpClient();
                    go.await();
                    for (int i = 0; i < perThread; i++) {
                        HttpResponse<String> r = client.send(HttpRequest.newBuilder(URI.create(base + "/apdu"))
                            .POST(HttpRequest.BodyPublishers.ofString("{\"hex\":\"B001000000\"}")).build(),
                            HttpResponse.BodyHandlers.ofString());
                        JsonObject o = json(r);
                        if (r.statusCode() == 200 && "9000".equals(o.get("sw").getAsString())
                            && o.get("hex").getAsString().length() == 64) {
                            ok.incrementAndGet();
                        } else {
                            synchronized (failures) { failures.add(new AssertionError(r.statusCode() + " " + r.body())); }
                        }
                    }
                } catch (Throwable e) {
                    synchronized (failures) { failures.add(e); }
                }
            });
            pool.add(th);
            th.start();
        }
        go.countDown();
        for (Thread th : pool) th.join(60_000);
        assertTrue(failures.isEmpty(), () -> "failures: " + failures);
        assertEquals(threads * perThread, ok.get());
    }

    @Test
    @DisplayName("a second start() on the same port throws BindException (main exits 2)")
    void busyPort() {
        assertThrows(BindException.class, () -> CardSim.start(sim.port()));
    }

    @Test
    @DisplayName("a card that cannot be built fails start() (main exits 1) and releases the port")
    void cardBuildFailureFailsStart() throws Exception {
        // The failure SimCard raises when the applet does not answer a 2.x
        // version after install. It used to surface as a 500 on the first
        // request, after main had already printed "listening".
        sim.stop();
        int port = sim.port();
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> CardSim.start(port, () -> {
            throw new IllegalStateException("SELECT after install answered 01149000, not a 2.x applet");
        }));
        assertTrue(e.getMessage().contains("not a 2.x applet"), e.getMessage());

        // The failed start stopped its server: the same port binds again and serves.
        sim = CardSim.start(port);
        assertEquals(200, get("/state").statusCode());
    }

    @Test
    @DisplayName("GET /state carries counts {unspent, spent, empty} next to slots")
    void stateCounts() throws Exception {
        JsonObject fresh = json(get("/state")).getAsJsonObject("counts");
        assertEquals(0, fresh.get("unspent").getAsInt());
        assertEquals(0, fresh.get("spent").getAsInt());
        assertEquals(128, fresh.get("empty").getAsInt());

        String proof = "{\"keysetId\":\"0059534ce0bfa19a\",\"amount\":8,\"nonce\":\"" + "ab".repeat(32)
            + "\",\"C\":\"02" + "11".repeat(32) + "\"}";
        JsonObject loaded = json(post("/fixture", "{\"mint\":\"http://m\",\"owner\":true,\"proofs\":[" + proof + "]}")).getAsJsonObject("counts");
        assertEquals(1, loaded.get("unspent").getAsInt());
        assertEquals(0, loaded.get("spent").getAsInt());
        assertEquals(127, loaded.get("empty").getAsInt());
    }
}
