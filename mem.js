/**
 * # mem.js — Class-based DFIR Memory Wrapper (Node API)
 *
 * This file exposes a **class-oriented** API for interacting with the native layer:
 *
 * - `memory.node` (Node-API addon)
 * - `memory-helper.dll` (native Windows DLL)
 *
 * The goal is to provide **ergonomic objects** instead of loose primitives.
 *
 * ✅ Everything returned is a **class instance**:
 * - `findProcessesByName()` returns `ProcessList`
 * - `new Service("DcomLaunch")` returns `Service`
 * - `service.process()` returns `Process`
 * - `process.scanStrings()` returns `ScanResult`
 * - each hit is a `StringHit`
 *
 * ---
 *
 * ## Auto-close behavior (IMPORTANT)
 *
 * By default, `Process` uses:
 *
 * - `autoClose: true` ✅
 *
 * Meaning:
 *
 * - If you never explicitly open a handle, methods like `scanStrings()` and `readMemory()`
 *   will open a process handle **only for the duration of that call**, then close it.
 * - This is deterministic and prevents handle leaks in DFIR scripts.
 *
 * If you *want to keep a handle open* (performance / repeated reads), call:
 *
 * - `proc.open()`  → pins the handle open until you call `proc.close()`.
 *
 * You can also disable autoClose:
 *
 * - `proc.autoClose = false` (then methods will keep the implicitly-opened handle)
 *
 * > There is also a `FinalizationRegistry` fallback that attempts to close pinned handles
 * > when the `Process` object is garbage-collected, but **GC timing is not deterministic**.
 * > Always prefer explicit `close()` for pinned handles.
 *
 * ---
 *
 * ## Threading / performance note
 *
 * All functions are synchronous (blocking). For large memory scans:
 * - Run Node as admin
 * - Consider worker threads / child processes for non-blocking CLI tools
 */

const addon = require('./memory.node');

/**
 * Internal: best-effort safety net for leaked pinned handles.
 * - Only kicks in if user calls `open()` (pins handle) and forgets `close()`.
 * - Auto-close-per-operation does not rely on GC.
 */
const _finalizer =
    typeof FinalizationRegistry !== 'undefined'
        ? new FinalizationRegistry((handle) => {
              try {
                  if (handle) addon.closeHandle(handle);
              } catch {
                  // ignore
              }
          })
        : null;

/**
 * @typedef {Object} ScanOptions
 *
 * ## ScanOptions
 *
 * Options forwarded into the native string scanner.
 *
 * ### Common options
 *
 * - `contains?: string`
 *   - Only return hits containing this substring (native substring filter).
 * - `minLength?: number`
 *   - Minimum printable run length (native default is commonly 4).
 * - `ascii?: boolean`
 *   - Enable ASCII scanning (currently the only implemented scanner in your C file).
 * - `utf16?: boolean`
 *   - Present for forward-compat; **native currently ignores UTF-16**.
 * - `caseSensitive?: boolean`
 *   - Substring match sensitivity (native filter supports case-insensitive).
 * - `maxResults?: number`
 *   - Maximum number of hits emitted from native code.
 *
 * ### Advanced (if supported by your addon build)
 *
 * - `start?: bigint`
 * - `end?: bigint`
 *
 * These define an address range for scanning. If your addon/native doesn’t use them,
 * they will be ignored safely.
 */

/**
 * @typedef {Object} StringHitJSON
 * @property {bigint} address
 * @property {string} text
 * @property {string} encoding
 */

/**
 * # class Process
 *
 * Represents a single Windows process (by PID) and provides:
 *
 * - Handle lifecycle control (autoClose/pinned)
 * - Memory reads
 * - String scanning (returns classes, not raw objects)
 *
 * ---
 *
 * ## Construction
 *
 * Prefer:
 *
 * - `Process.fromPid(pid)`
 * - `findProcessesByName("java.exe")`
 * - `new Service("DcomLaunch").process()`
 *
 * But you can also:
 *
 * - `new Process(pid)`
 */
class Process {
    /**
     * @param {number} pid
     * @param {{ autoClose?: boolean }} [opts]
     */
    constructor(pid, opts = {}) {
        if (!Number.isInteger(pid) || pid <= 0) {
            throw new Error(`Process(pid): pid must be a positive integer, got: ${pid}`);
        }

        /** @type {number} */
        this.pid = pid;

        /**
         * If true (default), `readMemory()` / `scanStrings()` open a handle for the call,
         * then close it when the call ends (unless handle is pinned via `open()`).
         * @type {boolean}
         */
        this.autoClose = opts.autoClose !== undefined ? !!opts.autoClose : true;

        /** @type {bigint|null} */
        this._handle = null;

        /** @type {boolean} */
        this._opened = false;

        /**
         * If true, handle is "pinned" open by user calling `open()`.
         * autoClose will NOT close pinned handles.
         * @type {boolean}
         */
        this._pinned = false;

        /** @type {object} */
        this._finalizerToken = {};
    }

    /**
     * ## `Process.fromPid(pid: number): Process`
     *
     * Convenience constructor.
     *
     * ```js
     * const proc = Process.fromPid(1234);
     * ```
     */
    static fromPid(pid) {
        return new Process(pid);
    }

    /**
     * ## `isOpen(): boolean`
     *
     * Returns true if a process handle is currently open.
     * Note: handle may be open because:
     * - user pinned it with `open()`, OR
     * - autoClose is false and a prior operation opened it
     */
    isOpen() {
        return this._opened && !!this._handle;
    }

    /**
     * ## `open(): this`
     *
     * Pins a handle open for repeated operations.
     *
     * When pinned:
     * - `autoClose` will NOT close the handle after operations.
     * - You should call `close()` when done.
     *
     * ```js
     * proc.open();
     * const a = proc.readMemory(addr1, 1024);
     * const b = proc.readMemory(addr2, 1024);
     * proc.close();
     * ```
     */
    open() {
        this._pinned = true;
        this._openInternal();
        return this;
    }

    /**
     * ## `close(): void`
     *
     * Closes the handle if open.
     *
     * Safe to call multiple times.
     * If handle was pinned, this unpins it too.
     */
    close() {
        this._pinned = false;

        if (this._opened && this._handle) {
            try {
                addon.closeHandle(this._handle);
            } finally {
                this._opened = false;
                this._handle = null;

                if (_finalizer) {
                    try {
                        _finalizer.unregister(this._finalizerToken);
                    } catch {
                        // ignore
                    }
                }
            }
        }
    }

    /**
     * Internal: open handle if not already open.
     * Throws if open fails.
     */
    _openInternal() {
        if (this._opened && this._handle) return;

        const h = addon.openProcess(this.pid);
        if (!h || typeof h !== 'bigint' || h === 0n) {
            throw new Error(`Failed to open PID ${this.pid} (access denied / exited / insufficient privilege)`);
        }

        this._handle = h;
        this._opened = true;

        // Register for GC safety only if pinned.
        if (_finalizer && this._pinned) {
            try {
                _finalizer.unregister(this._finalizerToken);
            } catch {
                // ignore
            }
            _finalizer.register(this, h, this._finalizerToken);
        }
    }

    /**
     * Internal helper: executes `fn(handle)` with the correct autoClose semantics.
     *
     * - Opens handle if needed.
     * - If autoClose=true AND handle was not already open AND not pinned,
     *   closes after fn completes.
     *
     * @template T
     * @param {(handle: bigint) => T} fn
     * @returns {T}
     */
    _withHandle(fn) {
        const wasOpen = this.isOpen();
        if (!wasOpen) this._openInternal();

        try {
            return fn(this._handle);
        } finally {
            // Deterministic auto-close per call
            if (this.autoClose && !wasOpen && !this._pinned) {
                this.close();
            }
        }
    }

    /**
     * ## `readMemory(address: bigint|number, size=256): Buffer|null`
     *
     * Reads raw bytes from this process.
     *
     * - If `autoClose` is enabled and you did not call `open()`, the handle will be opened
     *   for this call and closed afterward.
     *
     * ### Parameters
     * - `address`: Virtual address in the target process
     * - `size`: Max bytes to read
     *
     * ### Returns
     * - `Buffer` on success
     * - `null` if the read fails
     */
    readMemory(address, size = 256) {
        return this._withHandle((h) => addon.readMemory(h, BigInt(address), size) || null);
    }

    /**
     * ## `readString(address: bigint|number, max=256): string|null`
     *
     * Best-effort string read:
     * - reads `max` bytes
     * - decodes as UTF-8
     * - strips NUL bytes
     * - trims whitespace
     *
     * This is for quick probing; for robust extraction use scanning.
     */
    readString(address, max = 256) {
        const buf = this.readMemory(address, max);
        if (!buf) return null;
        return buf.toString('utf8').replace(/\0/g, '').trim();
    }

    /**
     * ## `scanStrings(options?: ScanOptions): ScanResult`
     *
     * Scans the process memory for printable strings (ASCII in your current native code).
     *
     * ### Returns
     * A `ScanResult` object which:
     * - is iterable (`for..of`)
     * - has `.length`
     * - contains `StringHit` items with `.process` reference
     *
     * ### Example — scan for ".jar" with minimum length 4
     * ```js
     * const res = proc.scanStrings({ contains: ".jar", minLength: 4 });
     * console.log(res.length);
     * for (const hit of res) console.log(hit.toString());
     * ```
     */
    scanStrings(options = {}) {
        return this._withHandle((h) => {
            const raw = addon.scanStrings(h, options) || [];
            const hits = raw.map((obj) => new StringHit(this, obj));
            return new ScanResult(this, hits, options);
        });
    }

    /**
     * ## `toString(): string`
     */
    toString() {
        return `Process(pid=${this.pid}, open=${this.isOpen()}, pinned=${this._pinned}, autoClose=${this.autoClose})`;
    }
}

/**
 * # class StringHit
 *
 * Represents a single hit produced by the native scanner.
 *
 * - `address` is a BigInt
 * - `encoding` is currently `"ascii"` in your native implementation
 * - `text` is truncated natively (~511 chars)
 *
 * A `StringHit` always links back to the owning `Process`.
 */
class StringHit {
    /**
     * @param {Process} process
     * @param {StringHitJSON} raw
     */
    constructor(process, raw) {
        /** @type {Process} */
        this.process = process;

        /** @type {bigint} */
        this.address = raw.address;

        /** @type {string} */
        this.text = raw.text;

        /** @type {string} */
        this.encoding = raw.encoding;
    }

    /**
     * Pretty format for console output.
     */
    toString() {
        return `[PID ${this.process.pid}] 0x${this.address.toString(16)} [${this.encoding}] ${this.text}`;
    }

    /**
     * Minimal JSON-like representation (BigInt is preserved as BigInt).
     */
    toJSON() {
        return {
            pid: this.process.pid,
            address: this.address,
            encoding: this.encoding,
            text: this.text,
        };
    }
}

/**
 * # class ScanResult
 *
 * Wraps scan output for a single process. Provides convenience methods and keeps:
 * - owning `process`
 * - array of `hits` (StringHit)
 * - `options` used
 *
 * It is iterable and has `.length`.
 */
class ScanResult {
    /**
     * @param {Process} process
     * @param {StringHit[]} hits
     * @param {ScanOptions} options
     */
    constructor(process, hits, options) {
        /** @type {Process} */
        this.process = process;

        /** @type {StringHit[]} */
        this.hits = hits;

        /** @type {ScanOptions} */
        this.options = options;
    }

    /**
     * Number of hits.
     */
    get length() {
        return this.hits.length;
    }

    /**
     * Make ScanResult iterable: `for (const hit of result) { ... }`
     */
    [Symbol.iterator]() {
        return this.hits[Symbol.iterator]();
    }

    /**
     * ## `filter(fn): ScanResult`
     *
     * Returns a new ScanResult with filtered hits.
     *
     * ```js
     * const jarOnly = res.filter(h => h.text.includes(".jar"));
     * ```
     */
    filter(fn) {
        return new ScanResult(this.process, this.hits.filter(fn), this.options);
    }

    /**
     * ## `uniqueTexts(): string[]`
     *
     * Returns unique string payloads.
     */
    uniqueTexts() {
        return Array.from(new Set(this.hits.map((h) => h.text)));
    }

    /**
     * ## `toTable(): Array<{pid:number,address:string,encoding:string,text:string}>`
     *
     * Useful for `console.table(result.toTable())`.
     */
    toTable() {
        return this.hits.map((h) => ({
            pid: h.process.pid,
            address: `0x${h.address.toString(16)}`,
            encoding: h.encoding,
            text: h.text,
        }));
    }
}

/**
 * # class ProcessList
 *
 * Represents a collection of `Process` objects returned by discovery methods.
 *
 * - Iterable
 * - Has `.length`
 * - Provides `.scanStringsAll()` helper
 */
class ProcessList {
    /**
     * @param {Process[]} processes
     */
    constructor(processes) {
        /** @type {Process[]} */
        this.processes = processes;
    }

    get length() {
        return this.processes.length;
    }

    [Symbol.iterator]() {
        return this.processes[Symbol.iterator]();
    }

    /**
     * ## `scanStringsAll(options?: ScanOptions): MultiScanResult`
     *
     * Scans each process and returns a `MultiScanResult`.
     *
     * With default `autoClose=true`, each scan opens/closes handles per call.
     * If you want speed:
     * - call `proc.open()` for each process before scanning, then close later.
     */
    scanStringsAll(options = {}) {
        const results = this.processes.map((p) => p.scanStrings(options));
        return new MultiScanResult(results);
    }

    /**
     * Convenience: return raw array.
     */
    toArray() {
        return Array.from(this.processes);
    }
}

/**
 * # class MultiScanResult
 *
 * Represents a set of `ScanResult` objects (often one per process).
 *
 * It is iterable over *ScanResults*, and provides:
 * - `.totalHits`
 * - `.flattenHits()` → `HitList`
 */
class MultiScanResult {
    /**
     * @param {ScanResult[]} results
     */
    constructor(results) {
        /** @type {ScanResult[]} */
        this.results = results;
    }

    [Symbol.iterator]() {
        return this.results[Symbol.iterator]();
    }

    get totalHits() {
        return this.results.reduce((sum, r) => sum + r.length, 0);
    }

    /**
     * Flatten to a `HitList` (all hits across all processes).
     */
    flattenHits() {
        const all = [];
        for (const r of this.results) all.push(...r.hits);
        return new HitList(all);
    }
}

/**
 * # class HitList
 *
 * Represents a flat list of `StringHit` objects.
 * Useful for multi-process scans.
 */
class HitList {
    /**
     * @param {StringHit[]} hits
     */
    constructor(hits) {
        /** @type {StringHit[]} */
        this.hits = hits;
    }

    get length() {
        return this.hits.length;
    }

    [Symbol.iterator]() {
        return this.hits[Symbol.iterator]();
    }

    /**
     * Filter and keep as HitList.
     */
    filter(fn) {
        return new HitList(this.hits.filter(fn));
    }

    /**
     * Unique hit texts.
     */
    uniqueTexts() {
        return Array.from(new Set(this.hits.map((h) => h.text)));
    }

    /**
     * Group hits by PID.
     * @returns {Map<number, HitList>}
     */
    groupByPid() {
        const m = new Map();
        for (const h of this.hits) {
            const pid = h.process.pid;
            if (!m.has(pid)) m.set(pid, []);
            m.get(pid).push(h);
        }
        // convert arrays to HitList
        for (const [pid, arr] of m.entries()) {
            m.set(pid, new HitList(arr));
        }
        return m;
    }

    toTable() {
        return this.hits.map((h) => ({
            pid: h.process.pid,
            address: `0x${h.address.toString(16)}`,
            encoding: h.encoding,
            text: h.text,
        }));
    }
}

/**
 * # class Service
 *
 * Represents a Windows service by **service key name** (not display name).
 *
 * - `new Service("DcomLaunch")`
 * - `.pid` resolves immediately
 * - `.process()` returns a `Process`
 */
class Service {
    /**
     * @param {string} keyName
     */
    constructor(keyName) {
        if (typeof keyName !== 'string' || !keyName.trim()) {
            throw new Error('Service(keyName): keyName must be a non-empty string');
        }

        /** @type {string} */
        this.name = keyName;

        /** @type {number} */
        this.pid = addon.findServicePid(keyName);

        if (!this.pid) {
            throw new Error(`Service "${keyName}" not running or PID unavailable (returned 0)`);
        }
    }

    /**
     * ## `process(opts?): Process`
     *
     * Returns a `Process` instance for the service PID.
     *
     * ```js
     * const proc = new Service("DcomLaunch").process();
     * const res = proc.scanStrings({ contains: ".jar", minLength: 4 });
     * ```
     *
     * @param {{ autoClose?: boolean }} [opts]
     */
    process(opts = {}) {
        return new Process(this.pid, opts);
    }

    toString() {
        return `Service(name=${this.name}, pid=${this.pid})`;
    }
}

/**
 * ## `findProcessesByName(exeName: string, opts?): ProcessList`
 *
 * Returns a collection of `Process` objects matching the executable name.
 *
 * ```js
 * const procs = findProcessesByName("java.exe");
 * for (const p of procs) console.log(p.pid);
 * ```
 *
 * @param {string} exeName
 * @param {{ autoClose?: boolean }} [opts]
 * @returns {ProcessList}
 */
function findProcessesByName(exeName, opts = {}) {
    if (typeof exeName !== 'string') throw new Error('exeName must be a string');
    const pids = addon.findPidsByExeName(exeName) || [];
    const processes = pids.map((pid) => new Process(pid, opts));
    return new ProcessList(processes);
}

module.exports = {
    // Classes
    Process,
    Service,
    ProcessList,
    ScanResult,
    MultiScanResult,
    HitList,
    StringHit,

    // Discovery
    findProcessesByName,
};

/**
 * ---
 *
 * ## Quick usage examples
 *
 * ### Scan DcomLaunch for ".jar" min length 4
 *
 * ```js
 * const { Service } = require("./mem");
 *
 * const proc = new Service("DcomLaunch").process(); // autoClose=true by default
 * const res = proc.scanStrings({ contains: ".jar", minLength: 4 });
 *
 * for (const hit of res) console.log(hit.toString());
 * console.log("Hits:", res.length);
 * ```
 *
 * ### Scan all java.exe processes for ".jar"
 *
 * ```js
 * const { findProcessesByName } = require("./mem");
 *
 * const procs = findProcessesByName("java.exe"); // ProcessList
 * const multi = procs.scanStringsAll({ contains: ".jar", minLength: 4 });
 *
 * console.log("Total hits:", multi.totalHits);
 * console.table(multi.flattenHits().toTable());
 * ```
 *
 * ### Pin a handle open for performance
 *
 * ```js
 * const { findProcessesByName } = require("./mem");
 *
 * for (const proc of findProcessesByName("java.exe")) {
 *   proc.open(); // pin
 *   try {
 *     const res = proc.scanStrings({ contains: ".jar", minLength: 4 });
 *     console.log(proc.pid, res.length);
 *   } finally {
 *     proc.close();
 *   }
 * }
 * ```
 */
