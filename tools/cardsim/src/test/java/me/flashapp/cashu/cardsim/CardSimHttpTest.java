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
    @DisplayName("POST /apdu round-trips a SELECT")
    void apduRoundTrip() throws Exception {
        HttpResponse<String> r = post("/apdu", "{\"hex\":\"00A4040007D2760000850102\"}");
        assertEquals(200, r.statusCode());
        assertEquals("application/json", r.headers().firstValue("Content-Type").orElse(""));
        JsonObject o = json(r);
        assertEquals("00069000", o.get("hex").getAsString());
        assertEquals("9000", o.get("sw").getAsString());
    }

    @Test
    @DisplayName("a card refusal is still a 200: the transport worked")
    void refusalIs200() throws Exception {
        HttpResponse<String> r = post("/apdu", "{\"hex\":\"B0 13 1F 00 4E\"}"); // GET_PROOF of an empty slot
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
        HttpResponse<String> badLc = post("/apdu", "{\"hex\":\"B04300000531323334\"}");
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
        assertEquals("0.6", s.get("appletVersion").getAsString());
        assertEquals(66, s.get("pubkey").getAsString().length());
        assertEquals(32, s.getAsJsonArray("slots").size());
        assertTrue(s.get("deterministicKey").getAsBoolean());

        HttpResponse<String> r = post("/reset", "");
        assertEquals(200, r.statusCode());
        assertEquals(1, json(r).get("generation").getAsLong());
        assertEquals(s.get("pubkey").getAsString(), json(r).get("pubkey").getAsString(), "deterministic key");
    }

    @Test
    @DisplayName("POST /fixture applies and answers state; a refused step answers 409 {error, sw, state}")
    void fixture() throws Exception {
        HttpResponse<String> ok = post("/fixture", "{\"pin\":\"1234\",\"puk\":\"12345678\",\"blockedPin\":true}");
        assertEquals(200, ok.statusCode());
        assertEquals(2, json(ok).get("pinState").getAsInt());
        assertEquals(1, json(ok).get("pukState").getAsInt());
        assertEquals(1, json(ok).get("generation").getAsLong());

        HttpResponse<String> refused = post("/fixture", "{\"pin\":\"5678\"}");
        assertEquals(409, refused.statusCode());
        JsonObject o = json(refused);
        assertEquals("SET_PIN", o.get("error").getAsString());
        assertEquals("6985", o.get("sw").getAsString());
        JsonObject state = o.getAsJsonObject("state");
        assertEquals(2, state.get("generation").getAsLong());
        assertEquals("SET_PIN", state.getAsJsonObject("fixtureError").get("step").getAsString());
        assertEquals("SET_PIN", json(get("/state")).getAsJsonObject("fixtureError").get("step").getAsString());

        HttpResponse<String> after = post("/apdu", "{\"hex\":\"B021000020" + "00".repeat(32) + "40\"}");
        assertEquals("6982", json(after).get("sw").getAsString(), "the fixture's card is still blocked");
    }

    @Test
    @DisplayName("a version-masked fixture changes what /apdu answers")
    void maskedFixture() throws Exception {
        assertEquals(200, post("/fixture", "{\"appletVersion\":\"0.4\"}").statusCode());
        assertEquals("00049000", json(post("/apdu", "{\"hex\":\"00A4040007D2760000850102\"}")).get("hex").getAsString());
        assertEquals("6D00", json(post("/apdu", "{\"hex\":\"B0440000090831323334353637 38\"}")).get("sw").getAsString());
        assertEquals(200, post("/reset", "").statusCode());
        assertEquals("00069000", json(post("/apdu", "{\"hex\":\"00A4040007D2760000850102\"}")).get("hex").getAsString());
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
                            && o.get("hex").getAsString().length() == 22) {
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
}
