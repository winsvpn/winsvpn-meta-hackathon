# Root-owned CLI. The app database and bindings are data, never code.
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import argparse
import errno
import math
import secrets
import sqlite3
import stat
import threading

CANARY_RESULT_DIR = Path('/var/lib/wins-canary-results')
CANARY_REQUEST_DIR = Path('/var/lib/wins-canary-requests')
CANARY_STATE_DIR = Path('/var/lib/wins-canary-dispatch')
# At most one run per slug per interval (design 3.11, 10.3 P-12).
CANARY_MIN_INTERVAL_SECONDS = 60
# While a request is held by that limit, the spool is listed again at least
# this often, so a request for another slug is not held behind it.
CANARY_HOLD_POLL_SECONDS = 5
# Fixed names beside slug-derived ones (<slug>.json in the spool, <slug>.lock
# and <slug>.last in the state directory). A leading dot never matches the
# slug pattern, so no node can be named like them.
CANARY_DISPATCH_LOCK = '.dispatch.lock'
CANARY_REJECTED_DIR = '.rejected'
_canary_local = threading.local()


@contextmanager
def get_db():
    yield _canary_local.connection


def open_canary_database(path):
    # Type=simple can start a dependent unit before the hub's startup hook
    # retains its WAL sidecars. Probe the schema, since connect alone is lazy.
    for attempt in range(41):
        connection = None
        try:
            connection = sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True, timeout=30)
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA query_only=ON')
            connection.execute('PRAGMA busy_timeout=0')
            connection.execute('SELECT 1 FROM sqlite_schema LIMIT 1').fetchall()
            connection.execute('PRAGMA busy_timeout=30000')
            return connection
        except sqlite3.OperationalError:
            if connection is not None:
                connection.close()
            if attempt == 40:
                raise
        except Exception:
            if connection is not None:
                connection.close()
            raise
        time.sleep(0.25)


def run_canary_slug(connection, slug):
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}', slug):
        return False
    _canary_local.connection = connection
    row = connection.execute('SELECT * FROM nodes WHERE slug=?', (slug,)).fetchone()
    if row is None or dict(row).get('retired_at') or row['protocol_version'] != 'winn/3':
        return False
    # Capture a single SQLite snapshot before any subprocess. The result's
    # binding will be rejected if the row moves while the probe is running.
    connection.execute('BEGIN')
    try:
        row = connection.execute('SELECT * FROM nodes WHERE slug=?', (slug,)).fetchone()
        if (row is None or dict(row).get('retired_at') or row['protocol_version'] != 'winn/3'
                or dict(row).get('deployment_withdrawal_id') or not dict(row).get('deployment_released_at')):
            return False
        # Completion can leave a previous winn3 carrier in the row. Only a
        # flip committed after this deployment release is a live-profile run.
        if not row['winn3_carrier_flipped_at']:
            return False
        # The app's own parser, as in winn3_canary_is_fresh: an offset is
        # converted to UTC, a naive value is UTC, and a non-text marker (a
        # BLOB) or a malformed one is no proof.
        released = parse_iso_datetime(row['deployment_released_at'])
        flipped = parse_iso_datetime(row['winn3_carrier_flipped_at'])
        if released is None or flipped is None or flipped < released:
            return False
        profile = winn3_render_canary_profile(row)
        bindings, conflicts = winn3_canary_bindings()
        binding = bindings.get(slug)
        identity = winn3_identity_digest(profile)
        if not binding or slug in conflicts or row['winn3_identity_sha256'] != identity:
            return False
        generation = row['deployment_generation']
    finally:
        connection.rollback()
    if not claim_canary_slug(slug):
        # Refused only by the per-slug limit: the dispatcher holds the
        # request instead of dropping it.
        _canary_local.limited = True
        return False
    proof = winn3_probe_canary(profile, binding, generation, profile['seq'])
    result = {name: proof[name] for name in ('status', 'detail', 'identity_sha256', 'seq', 'generation')}
    result.update(slug=slug, checked_at=datetime.fromisoformat(proof['checked_at']).replace(tzinfo=timezone.utc).isoformat())
    winn3_write_canary_file(CANARY_RESULT_DIR, slug + '.json', winn3_canonical(result))
    # The app is root but receives this directory read-only in its mount
    # namespace. Group/other write is forbidden by the ingestion rule.
    os.chmod(CANARY_RESULT_DIR / (slug + '.json'), 0o644)
    return proof['status'] == 'ok'


def canary_limit_remaining(slug):
    """Seconds until the slug may run again; 0 when it may run now. The limit
    never fails open and never holds for the size of a clock jump: a stamp in
    the future (the clock moved back), or one that is not a finite number
    (nan and -inf parse as numbers), is reset to now and holds the slug for
    one full interval. A stamp that exists but cannot be read holds the slug
    for one interval without being rewritten, so a request waiting on it is
    held, never discarded."""
    stamp = CANARY_STATE_DIR / (slug + '.last')
    try:
        last = float(stamp.read_text())
    except FileNotFoundError:
        return 0.0
    except ValueError:
        last = None
    except OSError:
        logger.warning('Canary stamp for %s cannot be read; the slug is held', slug)
        return float(CANARY_MIN_INTERVAL_SECONDS)
    now = time.time()
    if last is None or not math.isfinite(last) or last > now:
        winn3_write_canary_file(CANARY_STATE_DIR, slug + '.last', str(now).encode())
        return float(CANARY_MIN_INTERVAL_SECONDS)
    return max(0.0, CANARY_MIN_INTERVAL_SECONDS - (now - last))


def claim_canary_slug(slug):
    import fcntl
    lock = os.open(CANARY_STATE_DIR / (slug + '.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        if canary_limit_remaining(slug) > 0:
            return False
        winn3_write_canary_file(CANARY_STATE_DIR, slug + '.last', str(time.time()).encode())
        return True
    finally:
        os.close(lock)


CANARY_DISPATCH_PASSES = 3
CANARY_DISPATCH_WORKERS = 4


def discard_canary_entry(directory, name):
    """Remove one spool entry without reading it. An empty directory is
    removed. A directory that is not empty is renamed, unwalked, to a random
    name inside CANARY_REJECTED_DIR: out of the spool's request names, so it
    cannot hold one of the 64 places of a listing, and on the spool's own
    mount (the unit's ReadWritePaths and StateDirectory entries are separate
    mounts under ProtectSystem=strict, and rename(2) does not cross mounts)."""
    try:
        info = os.lstat(name, dir_fd=directory)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode):
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass
        return
    try:
        os.rmdir(name, dir_fd=directory)
        return
    except FileNotFoundError:
        return
    except OSError as exc:
        if exc.errno not in (errno.ENOTEMPTY, errno.EEXIST):
            raise
    try:
        os.mkdir(CANARY_REJECTED_DIR, 0o700, dir_fd=directory)
    except FileExistsError:
        pass
    rejected = os.open(CANARY_REJECTED_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    try:
        os.rename(name, secrets.token_hex(16), src_dir_fd=directory, dst_dir_fd=rejected)
    finally:
        os.close(rejected)
    logger.warning('Canary request directory moved out of the spool')


def consume_canary_request(connection, directory, name, held=None):
    """Validate and unlink one spooled request. Returns the slug to probe, or
    None. A valid request that only the slug's limit refuses is not unlinked:
    it stays in the spool and (slug, seconds left) is appended to held."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 256:
                discard_canary_entry(directory, name)
                return None
            request = json.loads(stream.read(257))
        slug = name[:-5]
        if request != {'slug': slug}:
            os.unlink(name, dir_fd=directory)
            return None
        row = connection.execute('SELECT retired_at FROM nodes WHERE slug=?', (slug,)).fetchone()
        if row is None or row['retired_at']:
            os.unlink(name, dir_fd=directory)
            return None
        if held is not None:
            remaining = canary_limit_remaining(slug)
            if remaining > 0:
                held.append((slug, remaining))
                return None
        os.unlink(name, dir_fd=directory)
        return slug
    except (OSError, ValueError, TypeError, KeyError):
        logger.warning('Canary request refused')
        # Consume malformed names so the path unit cannot spin.
        try:
            discard_canary_entry(directory, name)
        except OSError:
            pass
        return None


def run_dispatched_slug(connection, slug):
    """Run one consumed request. When only the slug's limit refused it (the
    periodic canary claimed the slug after the request was consumed), the
    request is written back and the slug returned, so it is held, not lost."""
    _canary_local.limited = False
    try:
        run_canary_slug(connection, slug)
    except (ValueError, OSError, Winn3ContractError):
        logger.warning('Canary profile refused for %s', slug)
    if not getattr(_canary_local, 'limited', False):
        return None
    try:
        winn3_write_canary_file(CANARY_REQUEST_DIR, slug + '.json', winn3_canonical({'slug': slug}))
    except OSError:
        logger.warning('Canary request for %s could not be held', slug)
        return None
    return slug


def run_dispatched_slugs(connection, database, slugs):
    # H3-PERF (bounded parallel probes): independent slugs wait on the network,
    # not the CPU. Each worker owns a read-only connection of its own.
    # Returns the slugs whose requests were written back to be held.
    if database is None or len(slugs) < 2:
        return [slug for slug in [run_dispatched_slug(connection, slug) for slug in slugs] if slug]

    def work(slug):
        try:
            with closing(open_canary_database(database)) as own:
                return run_dispatched_slug(own, slug)
        except sqlite3.Error:
            logger.warning('Canary database unavailable for %s', slug)
            return None

    with ThreadPoolExecutor(max_workers=min(CANARY_DISPATCH_WORKERS, len(slugs))) as pool:
        return [slug for slug in pool.map(work, slugs) if slug]


def dispatch_canary_requests(connection, database=None):
    import fcntl
    lock = os.open(CANARY_STATE_DIR / CANARY_DISPATCH_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock)
        return
    directory = os.open(CANARY_REQUEST_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # H3-PERF (lost wake-up): a request that lands while this run executes
        # would be seen by neither this run nor a second one, because the second
        # fails the lock. Look again before releasing it, a bounded number of times.
        # A request refused only by its slug's limit is held in the spool and
        # run when the limit ends, never dropped. The spool is listed again at
        # least every CANARY_HOLD_POLL_SECONDS meanwhile, and each request is
        # waited for at most one interval plus one poll from when this run
        # first held it; past that it stays in the spool for the next run.
        passes = 0
        first_held = {}
        while True:
            names = sorted(name for name in os.listdir(directory)
                           if re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,62}\.json', name))[:64]
            held = []
            slugs = [slug for slug in (consume_canary_request(connection, directory, name, held)
                                       for name in names) if slug]
            progressed = len(names) > len(held)
            for slug in slugs:
                first_held.pop(slug, None)
            held.extend((slug, 0.0) for slug in run_dispatched_slugs(connection, database, slugs))
            if progressed:
                passes += 1
                if passes < CANARY_DISPATCH_PASSES:
                    continue
            now = time.monotonic()
            waits = []
            for slug, remaining in held:
                if now - first_held.setdefault(slug, now) < CANARY_MIN_INTERVAL_SECONDS + CANARY_HOLD_POLL_SECONDS:
                    waits.append(remaining)
                else:
                    logger.warning('Held canary request for %s left for the next run', slug)
            if not waits:
                break
            time.sleep(max(0.05, min(min(waits) + 0.2, CANARY_HOLD_POLL_SECONDS)))
    finally:
        os.close(directory)
        os.close(lock)


def require_root_canary_artifact(path):
    path = Path(path).resolve(strict=True)
    forbidden = ('/root/vpn_auth', '/var/lib/wins-hub-ssh', '/var/lib/wins-site-ai-tunnel',
                 '/var/lib/wins-security-alerts', '/var/lib/wins-canary-requests')
    if any(str(path) == root or str(path).startswith(root + '/') for root in forbidden):
        raise ValueError('canary-executable-is-app-writable')
    for item in (path, *path.parents):
        info = item.stat()
        if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise ValueError('canary-executable-is-not-root-owned')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--database', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--slug')
    group.add_argument('--requests', action='store_true')
    args = parser.parse_args()
    require_root_canary_artifact(os.getenv('WINN3_CANARY_BIN', '') or '/usr/local/bin/winn3-probe')
    require_root_canary_artifact(__file__)
    with open_canary_database(args.database) as connection:
        if args.requests:
            dispatch_canary_requests(connection, args.database)
            return 0
        return 0 if run_canary_slug(connection, args.slug) else 1


if __name__ == '__main__':
    raise SystemExit(main())
