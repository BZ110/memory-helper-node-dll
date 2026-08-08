# memory-helper-node-dll

Small Node.js wrapper for reading and scanning Windows process memory.

It uses:

* `mem.js` - JavaScript API
* `memory.node` - Node-API addon
* `memory-helper.dll` - native Windows memory functions

## Usage

```js
const { findProcessesByName } = require("./mem");

const processes = findProcessesByName("java.exe");

for (const proc of processes) {
    const results = proc.scanStrings({
        contains: ".jar",
        minLength: 4
    });

    for (const hit of results) {
        console.log(hit.toString());
    }
}
```

You can also scan a Windows service:

```js
const { Service } = require("./mem");

const proc = new Service("DcomLaunch").process();
const results = proc.scanStrings({ minLength: 4 });
```

## Features

* Find processes by executable name
* Find a process from a Windows service
* Read process memory
* Scan memory for ASCII strings
* Automatic process handle cleanup
* Optional persistent handles for repeated reads

## Requirements

* Windows
* Node.js
* `memory.node`
* `memory-helper.dll`
* Administrator privileges may be required
