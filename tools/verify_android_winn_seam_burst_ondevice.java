import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;

import org.winsvpn.app.WinnAwgLoopbackSeam;

/**
 * The Android Winn loopback seam burst regression, ON THE DEVICE.
 *
 * The JVM unit test proves the same class on the host. This runs the identical
 * class under ART on real Android hardware, because "the code is portable" is a
 * claim and a measurement on the device is evidence.
 *
 * Drives the REAL org.winsvpn.app.WinnAwgLoopbackSeam. The pump loop below is
 * shaped exactly like WinnTunnelBridge's inbound pump: read a datagram, then do
 * a blocking write. Before the fix both ran on one thread.
 */
public final class SeamBurstDriver {

    private static final int DATAGRAM_BYTES = 1073;   // real session's average OUTER size
    private static final int MAX_DATAGRAM = 1400;
    private static final long WRITE_STALL_MICROS = 60;

    private static byte[] datagram(int sequence) {
        byte[] bytes = new byte[DATAGRAM_BYTES];
        bytes[0] = 4; // transport data
        for (int i = 0; i < 8; i++) {
            bytes[8 + i] = (byte) ((((long) sequence) >> (8 * i)) & 0xff);
        }
        return bytes;
    }

    private static int sequenceOf(byte[] bytes) {
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value |= ((long) (bytes[8 + i] & 0xff)) << (8 * i);
        }
        return (int) value;
    }

    private static long field(String json, String key) {
        String needle = "\"" + key + "\":";
        int at = json.indexOf(needle);
        if (at < 0) return 0;
        int i = at + needle.length();
        long value = 0;
        while (i < json.length() && Character.isDigit(json.charAt(i))) {
            value = value * 10 + (json.charAt(i) - '0');
            i++;
        }
        return value;
    }

    private static void runCase(String label, int count, long paceMicros) throws Exception {
        final boolean[] seen = new boolean[count];

        WinnAwgLoopbackSeam seam = WinnAwgLoopbackSeam.Companion.open(
                MAX_DATAGRAM,
                new Function1<String, Unit>() {
                    @Override public Unit invoke(String reason) { return Unit.INSTANCE; }
                },
                new Function2<Boolean, String, Unit>() {
                    @Override public Unit invoke(Boolean lossy, String summary) {
                        System.out.println("    session line: " + summary);
                        return Unit.INSTANCE;
                    }
                });

        final AtomicBoolean running = new AtomicBoolean(true);
        final AtomicLong delivered = new AtomicLong(0);
        Thread pump = new Thread(() -> {
            byte[] buffer = new byte[MAX_DATAGRAM];
            while (running.get()) {
                int n;
                try {
                    n = seam.readOutgoingDatagram(buffer);
                } catch (Exception e) {
                    return;
                }
                if (n < 0) return;
                if (n == 0) continue;
                // THE BLOCKING WRITE, standing in for transport.writeFrame.
                long until = System.nanoTime() + WRITE_STALL_MICROS * 1000;
                while (System.nanoTime() < until) { /* busy-wait */ }
                if (n >= 16) {
                    int sequence = sequenceOf(buffer);
                    if (sequence >= 0 && sequence < count) seen[sequence] = true;
                }
                delivered.incrementAndGet();
            }
        });
        pump.setDaemon(true);
        pump.start();

        DatagramSocket producer = new DatagramSocket();
        InetSocketAddress target =
                new InetSocketAddress(InetAddress.getByName("127.0.0.1"), seam.getLocalPort());

        long startedMs = System.currentTimeMillis();
        long startedNanos = System.nanoTime();
        for (int i = 0; i < count; i++) {
            if (paceMicros > 0) {
                long due = startedNanos + (long) i * paceMicros * 1000;
                while (System.nanoTime() < due) { /* busy-wait */ }
            }
            byte[] bytes = datagram(i);
            producer.send(new DatagramPacket(bytes, bytes.length, target));
        }
        long elapsed = System.currentTimeMillis() - startedMs;

        Thread.sleep(3000); // let the chain drain

        String stats = seam.seamStatsJson();
        long accounted = field(stats, "seam_rx_ring_dropped")
                + field(stats, "seam_rx_oversize")
                + field(stats, "seam_rx_foreign_sender");

        int arrived = 0;
        for (boolean b : seen) if (b) arrived++;
        int lost = count - arrived;
        long unaccounted = lost - accounted;

        System.out.println("--- " + label + " ---");
        System.out.println("  offered=" + count + " delivered=" + arrived + " lost=" + lost
                + "  elapsed=" + elapsed + "ms  rate="
                + (elapsed > 0 ? (count * 1000L / elapsed) : 0) + "/s");
        System.out.println("  accounted=" + accounted + "   UNACCOUNTED=" + unaccounted);
        System.out.println("  " + stats);
        if (unaccounted == 0) {
            System.out.println("  PASS  every lost datagram is in a counter");
        } else {
            System.out.println("  FAIL  " + unaccounted
                    + " datagrams vanished with NO counter anywhere — kernel receive-queue drops");
        }
        running.set(false);
        producer.close();
        seam.close();
        pump.join(1000);
        System.out.println();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== Android Winn loopback seam — burst regression, ON DEVICE ===");
        System.out.println("runtime: " + System.getProperty("java.vm.name")
                + " " + System.getProperty("java.vm.version")
                + "  os.arch=" + System.getProperty("os.arch"));
        System.out.println("datagram: " + DATAGRAM_BYTES + " bytes\n");

        runCase("CASE 1 burst of record (4 MiB, unpaced)", 4195, 0);
        runCase("CASE 2 sustained overload (3x, unpaced)", 12585, 0);
        runCase("CASE 3 paced 200us (the pre-existing proof must not regress)", 2000, 200);
    }
}
