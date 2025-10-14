import pickle, json, pathlib, datetime, collections, sys, types, zlib, gzip, bz2, lzma, binascii, io, pickletools

PERSISTENT_PATH = pathlib.Path("persistent")
OUTPUT_JSON = pathlib.Path("persistent-fran.json")

def _install_renpy_stubs():
    """
    Install lightweight stub modules for the `renpy` package so that
    pickled Ren'Py persistent objects can be safely unpickled without
    requiring the full Ren'Py engine.

    The stubs:
    - Provide placeholder classes (Persistent, RevertableList/Dict/Set, Preferences)
    - Accept arbitrary pickle state without raising errors
    - Emulate common unpickling patterns used by Ren'Py (tuple formats, dict merging)

    This function is idempotent: if `renpy` is already in `sys.modules`, it returns early.
    """
    if "renpy" in sys.modules:
        return
    renpy = types.ModuleType("renpy")
    renpy.__path__ = []

    persistent_mod = types.ModuleType("renpy.persistent")
    revertable_mod = types.ModuleType("renpy.revertable")
    preferences_mod = types.ModuleType("renpy.preferences")

    class _BaseStub(object):
        def __setstate__(self, state):
            if isinstance(state, dict):
                self.__dict__.update(state)
            else:
                self._raw_state = state
        def __getstate__(self):
            return getattr(self, "__dict__", {})

    class Persistent(_BaseStub):
        pass

    class RevertableList(list, _BaseStub):
        def __setstate__(self, state):
            if isinstance(state, tuple) and len(state) == 2 and isinstance(state[1], dict):
                items, d = state
                self[:] = list(items)
                self.__dict__.update(d)
            else:
                _BaseStub.__setstate__(self, state)

    class RevertableDict(dict, _BaseStub):
        def __setstate__(self, state):
            if isinstance(state, tuple) and len(state) == 2 and isinstance(state[1], dict):
                items, d = state
                self.clear()
                self.update(items)
                self.__dict__.update(d)
            elif isinstance(state, dict):
                self.update(state)
            else:
                _BaseStub.__setstate__(self, state)

    class RevertableSet(set, _BaseStub):
        def __setstate__(self, state):
            def _add_items(items):
                for it in items:
                    try:
                        # Attempt to add directly
                        self.add(it)
                    except TypeError:
                        # Fallback: stable representation
                        self.add(repr(it))
            if isinstance(state, tuple):
                # Possible formats:
                # 1) (iterable, dict_state)
                # 2) (iterable,)
                if len(state) >= 1 and isinstance(state[0], (list, tuple, set)):
                    self.clear()
                    _add_items(state[0])
                    # Optional dict_state
                    if len(state) >= 2 and isinstance(state[1], dict):
                        self.__dict__.update(state[1])
                    return
            if isinstance(state, (list, tuple, set)):
                self.clear()
                _add_items(state)
                return
            if isinstance(state, dict):
                # Rare state: treat keys as elements
                self.clear()
                _add_items(state.keys())
                return
            _BaseStub.__setstate__(self, state)

    class Preferences(_BaseStub):
        pass

    persistent_mod.Persistent = Persistent
    revertable_mod.RevertableList = RevertableList
    revertable_mod.RevertableDict = RevertableDict
    revertable_mod.RevertableSet = RevertableSet
    preferences_mod.Preferences = Preferences

    sys.modules["renpy"] = renpy
    sys.modules["renpy.persistent"] = persistent_mod
    sys.modules["renpy.revertable"] = revertable_mod
    sys.modules["renpy.preferences"] = preferences_mod

def to_jsonable(obj):
    """
    Convert arbitrary Python objects (including custom Ren'Py persistent
    structures) into JSON-serializable forms.

    Rules:
    - Primitive scalars and None pass through unchanged
    - Lists / tuples / sets become lists (recursively processed)
    - Dicts and Mapping subclasses become dicts with stringified keys
    - datetime/date/time objects are serialized via ISO 8601 strings
    - Any other object becomes a descriptor dict with __type__ and __repr__

    Parameters:
        obj: Any Python object.

    Returns:
        A JSON-serializable structure (nested primitives / dicts / lists).
    """
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    if isinstance(obj, (list, tuple, set)):
        return [to_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (datetime.datetime, datetime.date, datetime.time)):
        return obj.isoformat()
    if isinstance(obj, collections.abc.Mapping):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    return {"__type__": type(obj).__name__, "__repr__": repr(obj)}

def load_persistent_bytes(path: pathlib.Path) -> bytes:
    """
    Read raw bytes from the given persistent file path.

    Parameters:
        path: Path object pointing to the serialized persistent file.

    Returns:
        Raw bytes read from disk.
    """
    return path.read_bytes()

def _maybe_decompress(raw: bytes) -> bytes:
    """
    Attempt a simple zlib decompression if the data appears to begin
    with a common zlib header (0x78). If decompression fails, return
    the original bytes.

    Parameters:
        raw: Input byte sequence.

    Returns:
        Possibly decompressed bytes, or the original input.
    """
    if len(raw) >= 2 and raw[0] == 0x78:
        try:
            return zlib.decompress(raw)
        except Exception:
            pass
    return raw

def _latin1_load(data: bytes):
    """
    Load a pickle (often protocol 2 from Python 2) forcing latin1 decoding
    and installing Ren'Py stubs for compatibility.

    The function also normalizes certain padded headers (null bytes after
    the protocol opcode).

    Parameters:
        data: Raw pickle bytes.

    Returns:
        The unpickled Python object.
    """
    # Normalize header: remove null padding after proto
    if data.startswith(b"\x80") and len(data) > 4 and data[2:6].startswith(b"\x00\x00"):
        i = 2
        while i < len(data) and data[i] == 0x00:
            i += 1
        data = data[:2] + data[i:]
    try:
        return pickle.loads(data, fix_imports=True, encoding="latin1", errors="ignore")
    except UnicodeDecodeError:
        # Final relaxed attempt
        return pickle.loads(data, fix_imports=True, encoding="latin1", errors="replace")

def _primary_big_blob(raw: bytes):
    """
    Fast-path heuristic:
    - If the raw data looks like zlib, decompress.
    - If the decompressed blob starts with a protocol 2 pickle header,
      attempt latin1 unpickling of the entire blob.
    - If that fails, attempt trimming at the first STOP opcode and retry.

    Parameters:
        raw: Raw input bytes (possibly compressed).

    Returns:
        Unpickled object on success; None if heuristic does not succeed.
    """
    # Detect zlib header variants (78 01 / 78 5e / 78 9c / 78 da)
    if raw.startswith(b"\x78"):
        try:
            dec = zlib.decompress(raw)
            if dec.startswith(b"\x80\x02"):
                try:
                    return _latin1_load(dec)
                except Exception:
                    # Try trimming at the first STOP in case of trailing garbage
                    trimmed = _slice_at_first_stop(dec)
                    if trimmed is not dec and trimmed.startswith(b"\x80\x02"):
                        return _latin1_load(trimmed)
        except Exception:
            pass
    return None

def _try_pickle_loads(data: bytes):
    """
    Attempt standard pickle loading, trying multiple encodings for
    Python 2 -> Python 3 transitional data (latin1, cp1252, utf-8).
    Falls back to a final latin1 replace strategy.

    Parameters:
        data: Pickle byte sequence.

    Returns:
        Unpickled object.
    """
    try:
        return pickle.loads(data)
    except UnicodeDecodeError:
        pass
    for enc in ("latin1", "cp1252", "utf-8"):
        try:
            return pickle.loads(data, fix_imports=True, encoding=enc, errors="ignore")
        except UnicodeDecodeError:
            continue
        except Exception:
            continue
    return pickle.loads(data, fix_imports=True, encoding="latin1", errors="replace")

MAX_PROTO = pickle.HIGHEST_PROTOCOL

def _is_pickle_candidate(buf: bytes, offset=0):
    """
    Heuristic check to see if a given offset in a byte buffer may
    mark the start of a pickle stream (0x80, protocol byte, within supported range).

    Parameters:
        buf: Byte buffer.
        offset: Position to inspect.

    Returns:
        True if it looks like a pickle header, else False.
    """
    if len(buf) - offset < 2:
        return False
    if buf[offset] != 0x80:
        return False
    proto = buf[offset+1]
    return proto <= MAX_PROTO

def _extract_pickle_slices(data: bytes):
    """
    Scan the data for potential pickle headers (0x80 followed by a plausible protocol byte).

    Parameters:
        data: Raw byte sequence.

    Returns:
        List of integer offsets where candidate pickles start.
    """
    offs = []
    idx = 0
    while True:
        pos = data.find(b'\x80', idx)
        if pos < 0:
            break
        if _is_pickle_candidate(data, pos):
            offs.append(pos)
        idx = pos + 1
    return offs

def _zlib_attempts(raw: bytes):
    """
    Attempt multiple zlib decompressions using alternate wbits configurations
    and searching for embedded zlib signatures within the data.

    Parameters:
        raw: Input bytes.

    Returns:
        List of successful decompressed byte sequences (may contain duplicates).
    """
    attempts = []
    for wbits in (15, -15):
        try:
            attempts.append(zlib.decompress(raw, wbits))
        except Exception:
            pass
    # Search for internal zlib headers
    for sig in (b'\x78\x01', b'\x78\x9c', b'\x78\xda', b'\x78\x5e'):
        inner = raw.find(sig)
        if inner > 0:
            for wbits in (15, -15):
                try:
                    attempts.append(zlib.decompress(raw[inner:], wbits))
                except Exception:
                    pass
    return attempts

def _maybe_decompress_variants(raw: bytes) -> list[bytes]:
    """
    Generate a list of decompression variants (including the original):
    - Raw bytes
    - zlib (multiple strategies)
    - gzip
    - bzip2
    - lzma/xz
    De-duplicates while preserving order.

    Parameters:
        raw: Raw input bytes.

    Returns:
        List of distinct candidate decompressed byte sequences.
    """
    outs = [raw]
    # Direct compression variants
    outs.extend(_zlib_attempts(raw))
    # gzip
    if raw.startswith(b"\x1f\x8b"):
        try:
            outs.append(gzip.decompress(raw))
        except Exception:
            pass
    # bz2
    if raw.startswith(b"BZh"):
        try:
            outs.append(bz2.decompress(raw))
        except Exception:
            pass
    # xz / lzma
    if raw.startswith(b"\xfd7zXZ") or raw[:1] == b"\x5d":
        try:
            outs.append(lzma.decompress(raw))
        except Exception:
            pass
    # Deduplicate preserving order
    uniq, seen = [], set()
    for b in outs:
        if b not in seen:
            seen.add(b); uniq.append(b)
    return uniq

def _load_single_pickle(data: bytes):
    """
    Robust single pickle loader that:
    - Tries standard unpickling with multiple encodings
    - On known error patterns (truncation, invalid keys), iteratively trims
      at potential STOP opcodes and retries.

    Parameters:
        data: Byte sequence likely representing a pickle.

    Returns:
        Unpickled object on success.

    Raises:
        Exception if no strategy succeeds.
    """
    try:
        return _try_pickle_loads(data)
    except Exception as e:
        msg = str(e)
        if isinstance(e, pickle.UnpicklingError) or "invalid load key" in msg or "pickle data was truncated" in msg or isinstance(e, UnicodeDecodeError):
            stop_byte = 0x2e
            tried = 0
            for pos in reversed([i for i,b in enumerate(data) if b == stop_byte]):
                if pos < 16:
                    continue
                tried += 1
                if tried > 300:
                    break
                slice_ = data[:pos+1]
                try:
                    return _try_pickle_loads(slice_)
                except Exception:
                    continue
        raise

def _split_concatenated(data: bytes):
    """
    If multiple pickles are concatenated (each starting with 0x80),
    split them into individual candidate segments.

    Parameters:
        data: Raw bytes.

    Returns:
        List of candidate pickle byte segments.
    """
    heads = [i for i in range(len(data)) if data.startswith(b'\x80', i)]
    if len(heads) <= 1:
        return [data]
    segments = []
    for idx, start in enumerate(heads):
        end = heads[idx+1] if idx+1 < len(heads) else len(data)
        segments.append(data[start:end])
    return segments

def _slice_at_first_stop(data: bytes) -> bytes:
    """
    Parse pickle opcodes until STOP and return an exact slice including the STOP.
    If parsing fails, returns the original data unchanged.

    Parameters:
        data: Candidate pickle byte sequence.

    Returns:
        Slice ending at the first STOP opcode (inclusive), or original data.
    """
    try:
        # pickletools.genops yields (opcode, arg, pos); pos is the opcode index
        for opcode, arg, pos in pickletools.genops(data):
            if opcode.name == "STOP":
                return data[:pos+1]
    except Exception:
        pass
    return data

# Set of valid opcode bytes (used to detect zero padding after the protocol)
_OPCODE_BYTES = {getattr(op, "code", None) for op in pickletools.opcodes if hasattr(op, "code")}

def _strip_proto_padding(data: bytes) -> bytes:
    """
    If after the header (0x80, protocol) there are null (0x00) bytes acting
    as padding before a valid opcode byte, remove that padding.

    Parameters:
        data: Raw pickle bytes.

    Returns:
        Possibly normalized pickle bytes with padding removed.
    """
    if len(data) > 3 and data[0] == 0x80:
        i = 2
        while i < len(data) and data[i] == 0x00:
            i += 1
        if i > 2 and i < len(data) and data[i] in _OPCODE_BYTES:
            return data[0:2] + data[i:]
    return data

def _extract_main_pattern_slice(blob: bytes) -> list[bytes]:
    """
    Search for typical start patterns referencing 'renpy.persistent' and
    extract candidate pickle slices (from header 0x80 to STOP).

    Parameters:
        blob: Byte sequence to scan.

    Returns:
        List of candidate pickle byte slices.
    """
    out = []
    if b"renpy.persistent" in blob:
        idx = 0
        while True:
            pos = blob.find(b"renpy.persistent", idx)
            if pos < 0:
                break
            # Walk backward to previous 0x80 header
            start = blob.rfind(b"\x80", 0, pos)
            if start >= 0 and _is_pickle_candidate(blob, start):
                segment = blob[start:]
                segment = _slice_at_first_stop(segment)
                out.append(segment)
            idx = pos + 1
    return out

def _optimize_pickle(data: bytes) -> bytes:
    """
    Attempt pickle bytecode optimization (removing unnecessary opcodes).
    If optimization fails, return original data unchanged.

    Parameters:
        data: Pickle byte sequence.

    Returns:
        Optimized pickle bytes or original argument.
    """
    try:
        return pickletools.optimize(data)
    except Exception:
        return data

def _dedupe(seq):
    """
    Deduplicate elements of a sequence while preserving order.

    Parameters:
        seq: Iterable of hashable elements.

    Returns:
        List with duplicates removed (first occurrence kept).
    """
    seen = set(); out = []
    for b in seq:
        if b not in seen:
            seen.add(b); out.append(b)
    return out

def try_unpickle(raw: bytes):
    """
    Comprehensive unpickling pipeline:
    1. Fast-path attempt on zlib + protocol 2 big blob.
    2. Generate decompression variants (zlib, gzip, bz2, lzma).
    3. Extract pattern-based candidate slices referencing 'renpy.persistent'.
    4. Split concatenated pickles, scan for headers inside blobs.
    5. Normalize (strip protocol padding, trim at STOP, optimize).
    6. Score and attempt loads (latin1 first for protocol 2).
    7. Employ layered fallbacks: direct load, trimmed load, single pickle loader.

    Parameters:
        raw: Raw persistent file bytes (possibly compressed or concatenated).

    Returns:
        Unpickled Python object (ideally a Persistent-like structure).

    Raises:
        RuntimeError if all attempts fail.
    """
    # (0) Fast path: decompress & load entire blob via latin1
    quick = _primary_big_blob(raw)
    if quick is not None:
        print("[OK] Loaded via fast-path big blob (latin1).")
        return quick

    candidates = []
    blobs = _maybe_decompress_variants(raw)
    candidates.extend(blobs)
    pattern_slices = []
    for blob in blobs:
        pattern_slices.extend(_extract_main_pattern_slice(blob))
    candidates.extend(pattern_slices)
    for blob in list(blobs):
        for seg in _split_concatenated(blob):
            candidates.append(seg)
        for off in _extract_pickle_slices(blob):
            candidates.append(blob[off:])

    norm = []
    for c in candidates:
        if not c.startswith(b"\x80"):
            continue
        base = _strip_proto_padding(c)
        sliced = _slice_at_first_stop(base)
        norm.append(base)
        if sliced is not base:
            norm.append(sliced)
        norm.append(_optimize_pickle(sliced))
    if not norm:
        norm = candidates

    filtered = [c for c in norm if c.startswith(b"\x80") and _is_pickle_candidate(c, 0)]
    if not filtered:
        filtered = norm

    def _score(b):
        return (1 if b.find(b"renpy.persistent") != -1 else 0, len(b))
    ordered = sorted(_dedupe(filtered), key=_score, reverse=True)

    last_err = None
    for idx, blob in enumerate(ordered):
        # Prioritize latin1 for protocol 2
        if blob.startswith(b"\x80\x02"):
            try:
                obj = _latin1_load(blob)
                print(f"[OK] Variant #{idx} latin1 direct len={len(blob)}")
                return obj
            except Exception as e:
                last_err = e
        try:
            obj = _try_pickle_loads(blob)
            print(f"[OK] Variant #{idx} standard len={len(blob)}")
            return obj
        except Exception:
            try:
                trimmed = _slice_at_first_stop(_strip_proto_padding(blob))
                if trimmed is not blob:
                    obj = _try_pickle_loads(trimmed)
                    print(f"[OK] Variant #{idx} trim len={len(trimmed)}")
                    return obj
            except Exception:
                pass
            try:
                obj = _load_single_pickle(blob)
                print(f"[OK] Variant #{idx} fallback len={len(blob)}")
                return obj
            except Exception as e2:
                last_err = e2
                if idx < 3:
                    print(f"[FAIL] Var #{idx} len={len(blob)} head={blob[:24]!r} err={e2!r}")
                continue

    print("DEBUG variants after failures (top 5):")
    for i, b in enumerate(ordered[:5]):
        print(f"Variant {i} len={len(b)} head={b[:24]!r}")
    raise RuntimeError(f"Unpickling failed. Last error: {last_err!r}")

def main():
    """
    Entry point:
    1. Install Ren'Py stubs.
    2. Read raw persistent file bytes.
    3. Attempt robust unpickling (handling compression & corruption).
    4. Convert resulting object (or its __dict__) into JSON-safe structure.
    5. Write JSON to OUTPUT_JSON.

    Side effects:
        Prints diagnostic information and success/failure states.
    """
    _install_renpy_stubs()
    raw = load_persistent_bytes(PERSISTENT_PATH)
    print(f"Raw len={len(raw)} head={binascii.hexlify(raw[:32])}")
    data = try_unpickle(raw)
    root = data.__dict__ if hasattr(data, "__dict__") else data
    jsonable = to_jsonable(root)
    with OUTPUT_JSON.open("w", encoding="utf-8") as f:
        json.dump(jsonable, f, ensure_ascii=False, indent=2)
    print(f"Converted to {OUTPUT_JSON}")

if __name__ == "__main__":
    main()