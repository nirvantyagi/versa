# REST API and Redis storage

_Demonstration of an API with concurrent lookups and updates backed by a persistent store_ 

## Overview

Like in the main branch, the repository here is organized into modular packages. For each of these packages, structs that interface directly with a data structure (i.e. vectors, hashmaps) are modified to instead interact only with a storage abstraction layer. 

In the first step of this process, the abstraction layer implements the original in-memory data structures. In the second step of this process, the abstraction layer reads and writes the same data through a Redis database.

Example mem store: [https://github.com/nirvantyagi/versa/blob/redis/storage-layer/single_step_avd/src/merkle_tree_avd/store/mem_store/mod.rs#L20](https://github.com/nirvantyagi/versa/blob/redis/storage-layer/single_step_avd/src/merkle_tree_avd/store/mem_store/mod.rs#L20)

Example Redis store: [https://github.com/nirvantyagi/versa/blob/redis/storage-layer/single_step_avd/src/merkle_tree_avd/store/mem_store/mod.rs#L20](https://github.com/nirvantyagi/versa/blob/redis/storage-layer/single_step_avd/src/merkle_tree_avd/store/mem_store/mod.rs#L20)

Finally, we provide example code to instantiate a full history avd (FHAVD) with Redis storage using an off the shelf web server. The server implements three routes `/commit`, `/prove` and `/epoch`.

1) `/commit` simply writes the provided key-value pair into a queue of entries that should be included in the next epoch

2) `/prove` generates a lookup from the instantiated FHAVD for the current epoch

3) `/epoch` kicks off the transition of the state of the registry

It is possible to consume routes 1 & 2 while an epoch update is underway because it occurs in the background using a clone. When the clone has finished processing updates the pointer to the FHAVD that route 2 reads from is then swapped ([using some trickery](https://github.com/nirvantyagi/versa/blob/redis/storage-layer/server/src/main.rs#L110)). 

## Installation/Build

Like in the main branch, the same [installation sequence](https://github.com/nirvantyagi/versa/blob/master/README.md#installationbuild) is required.

In addition, a Redis instance must be accessible at the canonical port:address `redis://127.0.0.1/`

Finally, `cd` into the server directory and run `cargo run`
