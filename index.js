/**
 * 🐠 distributed anonymous metadata segment encryption layer for integrated 
 * storage (huh?) 
 *
 * @module damselfish
 */

'use strict';

const { homedir } = require('node:os');
const { join, extname } = require('node:path');
const { randomBytes } = require('node:crypto');
const { URL } = require('node:url');
const { stringify } = require('node:querystring');
const { statSync, existsSync, mkdirSync, readdirSync } = require('node:fs');
const { readFile, writeFile } = require('node:fs/promises');
const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');

const { Client, Server } = require('@yipsec/scarf');
const { Identity, Message } = require('@yipsec/rise');
const { TorContext } = require('@yipsec/bulb');
const { ScalingBloomFilter } = require('@yipsec/blossom').bloom;
const { Node, Contact, constants } = require('@yipsec/kdns');
const { consensus, events, log } = require('@yipsec/brig');
const { dag, tree } = require('@yipsec/merked');


class Storage {

  constructor(dirpath) {
    this.root = dirpath;

    if (!existsSync(this.root)) {
      mkdirSync(this.root, { recursive: true });
    } else {
      if (statSync(this.root).isFile()) {
        throw new Error('Invalid storage path');
      }
    }
  }

  has(key) {
    return Promise.resolve(this._exists(key));
  }

  get(hash) {
    return new Promise(async (resolve, reject) => {
      const infofile = join(this.root, hash + '.info');
      
      let data;

      try {
        data = await readFile(infofile);
      } catch (err) {
        return reject(err);
      }

      const meta = JSON.parse(data);
      const datafile = join(this.root, hash + '.part');

      let buffer;

      try {
        buffer = await readFile(datafile);
      } catch (err) {
        return reject(err);
      }

      const blob = buffer.toString('hex');
      
      resolve({ hash, meta, blob });
    });
  }

  put(hash, item) {
    return new Promise(async (resolve, reject) => {
      let { blob, meta } = item;

      blob  = Buffer.from(blob, 'hex');

      const info = JSON.stringify(meta);
      const blobInfoPath = join(this.root, key + '.info');
      const blobDataPath = join(this.root, key + '.part');

      try {
        await writeFile(blobDataPath, blob);
        await writeFile(blobInfoPath, info);
      } catch (err) {
        return reject(err);
      }
    });
  }

  del(key) {
    return new Promise(async (resolve, reject) => {
      if (!this._exists(key)) {
        return reject(new Error(key + ' not found'));
      }

      try {
        await unlink(path.join(this.root, key + '.info'));
        await unlink(path.join(this.root, key + '.part'));
      } catch (err) {
        return reject(err);
      }

      resolve();
    });
  }

  createReadStream() {
    const list = readdirSync(this.root).filter((filename) => {
      return extname(filename) === '.info';
    }).sort();
    const rStream = new Readable({
      objectMode: true,
      read: async () => {
        const info = list.shift();

        if (!info) {
          return rStream.push(null);
        }

        try {
          rStream.push(await this.get(info.split('.')[0]));
        } catch (err) {
          this.emit('error', err);
        }
      }
    });

    return rStream;
  }

  _exists(key) {
    return existsSync(path.join(this.root, key + '.info')) && 
      existsSync(path.join(this.root, key + '.part'));
  }

}

module.exports.Storage = Storage;


class Link extends URL {

  /**
   *
   *
   * @constructor
   */
  constructor(opts) {
    super(opts);

    this.protocol = 'damselfish:';
  }

  /**
   *
   *
   */
  static fromString(str) {
    return new Link(str);
  }

  /**
   *
   *
   *
   */
  toString() {
    return this.href;
  }

  /**
   *
   *
   *
   */
  static fromContact(contact) {
    return Link.fromString(
      `damselfish://${contact.fingerprint}?${stringify(contact.address)}`);
  }

  /**
   *
   *
   */
  toContact() {
    return new Contact(this.hostname, 
      Object.fromEntries(this.searchParams.entries()));
  }

}

module.exports.Link = Link;


class Config {

  static get DataDirectory() {
    return join(homedir(), '.damselfish');
  }

  static createDefaults(datadir) {
    return {
      DataDirectory: join(datadir, 'database.encrypted'),
      IdentityKeyPath: join(datadir, 'private_key.encrypted'),
      ClustersManifest: join(datadir, 'clusters_manifest.encrypted'),
      OnionKeyPath: join(datadir, 'address_key.encrypted'),
      LinkedClients: join(datadir, 'linked_clients.encrypted'),
      RoutingTable: join(datadir, 'routing_table.encrypted')
    };
  }

/**
   *
   *
   * @constructor
   * 
   */
  constructor(dataDirectory = Config.DataDirectory) {
    const DEFAULTS = Config.createDefaults(dataDirectory);

    this.DataDirectory = DEFAULTS.DataDirectory
    this.IdentityKeyPath = DEFAULTS.IdentityKeyPath;
    this.ClustersManifest = DEFAULTS.ClustersManifest;
    this.OnionKeyPath = DEFAULTS.OnionKeyPath;
    this.LinkedClients = DEFAULTS.LinkedClients;
    this.RoutingTable = DEFAULTS.RoutingTable;
  }

}

module.exports.Config = Config;


class Presence extends EventEmitter {

  static get Events() {
    return {
      Ready: Symbol('damselfish~Presence~Events#Ready'),
      ClientRegistered: Symbol('damselfish~Presence~Events#ClientRegistered'),
      ClientUnregistered: Symbol('damselfish~Presence~Events#ClientUnregistered'),
      TimelineUpdated: Symbol('damselfish~Presence~Events#TimelineUpdated'),
      DebugInfo: Symbol('damselfish~Presence~Events#DebugInfo')
    };
  }

  /**
   * Eclipse resistant identity implementation.
   * @external RiseIdentity
   * @see https://yipsec.io/rise
   */

 /**
   * Embedded Tor and controller.
   * @external TorContext
   * @see https://yipsec.io/bulb
   */

  /**
   * Kademlia DHT implementation.
   * @external Node
   * @see https://yipsec.io/kdns
   */

  /**
   * Raft implementation for log replication.
   * @external Cluster
   * @see https://yipsec.io/brig
   */

  /**
   * @type {object} PresenceOptions
   * @property {module:damselfish/storage~Storage} storage - DHT storage backend.
   * @property {external:RiseIdentity} identity - Identity keys.
   * @property {external:TorContext} tor - Tor controller context.
   * @property {external:Node} dht - Kademlia DHT implementation.
   * @property {external:Contact} contact - KDNS contact instance.
   * @property {external:Cluster[]} clusters - Array of Raft clusters.
   * @property {string[]} clients - Public keys of linked clients.
   */

  /**
   * Node.js EventEmitter.
   * @external EventEmitter
   * @see https://nodejs.org/en/learn/asynchronous-work/the-nodejs-event-emitter

  /**
   * Primary interface for damselfish. A presense is a context on the network 
   * that handles the protocol that maintains the wider network distributed 
   * hash table. A Presence also is a parent context for any number of clusters 
   * (sub network replicated log).
   *
   * @constructor
   * @extends external:EventEmitter
   * @param {PresenceOptions} options - Damselfish configuration options.
   */
  constructor(options) {
    super();

    // Manage peer connections in a map.
    this.peers = new Map();

    this.storage = options.storage;
    this.identity = options.identity;
    this.tor = options.tor;
    this.contact = options.contact;
    this.server = options.server;
    this.dht = options.dht;
    this.clusters = new Map();
    this.clients = new Set(options.clients);

    for (let c = 0; c < options.clusters.length; c++) {
      this.clusters.set(options.clusters[c].id, options.clusters[c]);
    }

    this._controlServers = new Map();

    this._bootstrap();
  }

  /**
   * Asynchronously create a damselfish presense.
   *
   * @param {Config} config - Instance configuration object.
   * @param {string} [password] - Used for encrypting private keys.
   * @returns {Promise.<Presence>}
   */ 
  static create(config, password = '') {
    config = config || new Config();

    return new Promise(async (resolve, reject) => {
      // Get an instance of where we are going to store DHT records locally.
      const storage = new Storage(config.DataDirectory);
      
      let identity, tor, address;

      try {
        identity = existsSync(config.identity)
          // If there is a file at the config.identity path, try to unlock it.
          ? await Identity.unlock(password, 
            await readFile(config.IdentityKeyPath))
          // Otherwise, generate a new identity
          : await Identity.generate(6, 90, 5);
        
        // Save the generated identity encrypted to disk.
        await writeFile(config.IdentityKeyPath, identity.lock(password))

        // Bootstrap a Tor context before doing anything else!
        tor = await TorContext.create();
      } catch (e) {
        // Do not proceed if either fail.
        return reject(e);
      }

      // The damselfish protocol includes a "return address" in messages, so 
      // receiving nodes can initiate connections to them later.
      const contact = new Contact({
        // Host will be an onion address.
        host: null,
        // Port will be the "virtual port" used for the onion service.
        port: null,
        // Valid damselfish contacts include a fingerprint and a valid Rise 
        // identity solution.
        ...identity.solution.toJSON()
      });

      // Create a kdns (kademlia-like) Node. This is our interface to the DHT.
      const dht = new Node(contact);

      // If there is a a routing table cached already, populated from it.
      if (existsSync(config.RoutingTable)) {
        const cachedContactList = Message.fromBuffer(
          await readFile(config.RoutingTable)
        ).decrypt(identity.secret.privateKey).unwrap();

        for (let fingerprint in cachedContactList) {
          dht.router.addContact(fingerprint, new Contact(
            cachedContactList[fingerprint],
            fingerprint
          ));
        }
      }

      // Handle routing table events and persist the table state.
      dht.router.events
        .on('contact_added', _persistRouterState)
        .on('contact_deleted', _persistRouterState);

      // Function to serialize the router state into an encrypted cache.
      async function _persistRouterState() {
        // Fingerprint<>Contact pairs will dump here.
        let routerDump = {};

        // The router is a set of 160 (B) buckets of up to 20 (K) contacts.
        const kBuckets = dht.router.values();
        
        // Iterate through the buckets and merge the existing dump.
        for (let b = 0; b < kBuckets.length; b++) {
          const kBucket = Object.fromEntries(kBuckets[b].entries())

          routerDump = {
            ...routerDump,
            ...kBucket
          };
        }

        // Write the router dump to an encrypted file.
        await writeFile(config.RoutingTable, identity.message(
          identity.secret.publicKey,
          routerDump
        ).toBuffer());
      }
      
      // Define static protocol for handling DHT message types. This
      const protocol = {
        
        // Kademlia PING operation, pass through to kdns.
        PING() { 
          dht.protocol.PING(...arguments); 
        },
        
        // Kademlia FIND_NODE operation, pass through to kdns.
        FIND_NODE() { 
          dht.protocol.FIND_NODE(...arguments);
        },
        
        // Kademlia FIND_VALUE operation, pass through to kdns.
        FIND_VALUE() { 
          dht.protocol.FIND_VALUE(...arguments);
        },
        
        // Kademlia STORE operation, pass through to kdns.
        STORE() { 
          dht.protocol.STORE(...arguments); 
        }

        // Other METHODs will be dynamically added in _bootstrap() while
        // segmenting clusters into namespaced methods on this.server.api.
      };

      // The RPC interface is exposed as a scarf API over a TCP socket that is
      // accessible *only* as a Tor onion service.
      const server = new Server(protocol, () => tor.createServer());

      // Bind our service to an available local port and submit HS descriptors.
      try {
        // If we have already created an onion service before, load the 
        // encrypted private key, decrypt it.
        let onion = existsSync(config.OnionKeyPath)
          ? Message.fromBuffer(await readFile(config.OnionKeyPath))
              .decrypt(identity.secret.privateKey)
              .unwrap()
          // Otherwise we will create one...
          : null;

        // Bind/create onion service.
        address = await server.server.listen({
          keyType: onion ? onion.privateKey.split(':')[0] : 'NEW',
          keyBlob: onion ? onion.privateKey.split(':')[1] : 'BEST'
        });

        // Encrypt the private key.
        onion = identity.message(identity.secret.publicKey, {
          privateKey: server.server.privateKey,
          serviceId: server.server.serviceId
        }).toBuffer();
        
        // Write the encrypted private key to disk.
        await writeFile(config.OnionKeyPath, onion);
      } catch (e) {
        return reject(e);
      }

      // Update our "return address" information shared with peers, now that 
      // we have an onion address and virtual port.
      contact.address.host = address.host;
      contact.address.port = address.port;

      const clustersManifest = existsSync(config.ClustersManifest)
        ? Message.fromBuffer(await readFile(config.ClustersManifest))
          .decrypt(identity.secret.privateKey)
          .unwrap()
        : [];

      // Setup clusters (groups of nodes replicating an encrypted log).
      const clusters = clustersManifest.map(async clusterDef => {
        // The peer list in the configuration is converted into a list of Peer 
        // objects.
        const peers = clusterDef.members.map(fingerprint => {
          return new consensus.Peer(fingerprint);
        });
        
        // Create a special key to store cluster config locally.
        const clusterKey = `.CLUSTER_${clusterDef.localkey}`;

        // Check there is a log file at the given path.
        const logState = storage.has(clusterKey)
          // Load it from disk.
          ? log.LogState.deserialize((await storage.get(clusterKey)).blob)
          // Otherwise just create a new one.
          : new log.LogState();

        // Create a cluster context.
        return new consensus.Cluster(clusterDef.localkey, peers, logState);
      });

      // We can now establish a Presence on the network.
      const presence = new Presence({
        storage,
        identity,
        tor,
        contact,
        server,
        dht,
        clusters
      });

      let linkedClients = existsSync(config.LinkedClients)
        ? Message.fromBuffer(await readFile(config.LinkedClients))
            .decrypt(identity.secret.privateKey)
            .unwrap()
        : {};

      for (let publicKey in linkedClients) {
        await presence.linkControllerClient(publicKey, linkedClients[publicKey]);
      }

      resolve(presence);
    });
  }

  /**
   * 

  /**
   * Setup networking and internal event handlers.
   *
   * @private
   */
  _bootstrap() {
    // The kdns node wants to send a peer a message.
    this.dht.on('message_queued', (method, params, target, send) => {
      this.send(target, method, params)
        .then(result => send(null, result), err => send(err));    
    });

    // The kdns node requests an entry from storage.
    this.dht.on('storage_get', async (hash, done) => {
      try {
        done(null, await this.storage.get(hash));
      } catch (err) {
        done(err);
      }
    });

    // The kdns node wants to store an entry.
    this.dht.on('storage_put', async (hash, data, done) => {
      try {
        done(null, await this.storage.put(hash, data));
      } catch (err) {
        done(err);
      }
    });

    // The kdns node wants to delete an entry.
    this.dht.on('storage_delete', async (hash, done) => {
      try {
        done(null, await this.storage.del(hash));
      } catch (err) {
        done(err);
      }
    });

    // The kdns node wants to replicate and needs all entries.
    this.dht.on('storage_replicate', (replicatorStream) => {
      this.storage.createReadStream().pipe(replicatorStream);
    });

    // The kdns node wants to expire and needs all entries.
    this.dht.on('storage_expire', (expirerStream) => {
      this.storage.createReadStream().pipe(expirerStream);
    });

    // Bootstrap all of our clusters.
    for (let cluster of this.clusters.values()) {
      // We need to link up the transport to each peer object in the cluster.
      for (let p = 0; p < cluster.peers.length; p++) {
        const peer = cluster.peers[p];

        // Deliver the message to the underlying hidden socket.
        peer.on(events.MessageQueued, (fingerprint, message) => {
          // The cluster ID is the RPC method namespace.
     const method = `CLUSTER_${cluster.id}/${message.constructor.method}`;

          this.send(this.dht.router.getContactById(fingerprint), 
            method, [message]).then(acked => acked, err => err); 
        });
      }

      // We need to persist each cluster's log state to disk periodically.
      // When an entry is commited is a time to do it.
      cluster.on(events.LogCommit, async (_logEntry) => {
        await this.storage.put(`.CLUSTER_${cluster.id}`, {
          blob: cluster.log.serialize().toString('hex'),
          meta: {
            timestamp: Date.now(),
            publisher: this.identity.fingerprint.toString('hex')
          }
        });
        this.emit(Presence.Events.TimelineUpdated, cluster.id, _logEntry);
      });

      // Get the protocol handlers for out cluster log replication.
      const cMethods = cluster.createProtocolMapping();
      
      // We need to create namespaced method handlers, so multiple clusters
      // exist on the same node.
      for (let method in cMethods) {
        this.server.api[`CLUSTER_${cluster.id}/${method}`] = cMethods[method];
      }
    }
    
    // Presence is ready and online.
    this.emit(Presence.Events.Ready);
  }

  /**
   * Returns a damselfish link for this presence.
   *
   * @returns {string}
   */
  get link() {
    return Link.fromContact(this.contact);
  }

  /**
   * Send a remote procedure call to the target.
   * 
   *
   */
  send(target, method, params) {
    return new Promise((resolve, reject) => { 
      // kdns uses Contact objects while brig uses Peer objects. They have
      // differing APIs, but we should be able to accepts either type.
      const id = target.fingerprint || target.id;

      // Load the client from the pool.
      let client = this.peers.get(id);

      if (!client) {
        // If we don't have a connection already, set one up.
        client = new Client(this.tor.createConnection);
       
        // Connect to the remote contact.
        client.stream.once('connect', () => {
          // Track this connection by it's ID.
          this.peers.set(id, client);
          // Call the remote procedure.
          client.invoke(method, params, (err, result) => {
            if (err) {
              return reject(err);
            }

            return resolve(result);
          });
        });

        // If the connection is severed then stop tracking.
        client.stream.once('error', (err) => {
          this.peers.delete(id);
        });

        client.connect(target.address.port);
      } else {
        // If we already have a good connection, just call the remote 
        // procedure.
        client.invoke(method, params, (err, result) => {
          if (err) {
            return reject(err);
          }

          return resolve(result);
        });
      }        
    });
  }

  /**
   * Creates a merkle graph from the provided buffer and iteratively store 
   * each leaf in the DHT.
   *
   * @param {buffer} buffer - Raw buffer to store.
   * @param {string} [aliasName] - Filename or alias name for the data.
   * @returns {Promise.<DagMetadata>}
   */
  writeGraph(buffer, aliasName) {
    return new Promise(async (resolve, reject) => {
      const merkleGraph = dag.DAG.fromBuffer(
          buffer,
          4 * 1024, // slice size in bytes
          tree.MerkleTree.DEFAULT_HASH_FUNC, // hash function to use on inputs
          false, // pad the last slice to the slice size
          false // if padLastSlice fill with random bytes?
      );

      // For every shard in the DAG, store it by its hash.
      for (let s = 0; s < merkleGraph.shards.length; s++) {
        try {
          await this.dht.iterativeStore(merkleGraph.leaves[s], 
            merkleGraph.shards[s]);
        } catch (err) {
          return reject(err);
        }
      }

      resolve(merkleGraph.toMetadata(aliasName));
    });
  }

  /**
   * Reconstructs a buffer from the provided graph metadata.
   *
   * @param {DagMetadata} graphMeta - JSON serialized DAG metadata.
   * @returns {Promise.<external:DAG>}
   */
  readGraph(graphMeta) {
    return new Promise(async (resolve, reject) => {
      try {
        // Collect the results of parallel blob lookups and concatenate them.
        resolve(dag.DAG.fromBuffer(Buffer.concat(
          await Promise.all(graphMeta.l.map(leaf => {
            return new Promise(async (resolve, reject) => {
              try {
                resolve(await this.dht.iterativeFindValue(leaf));
              } catch (err) {
                return reject(err);
              }
            });
          }))
        )));
      } catch (err) {
        return reject(err);
      }
    });
  }

  /**
   * Adds a contact to the routing table and initiates a lookup. Routing table 
   * is persisted to maintain updated local contact list cache.
   *
   * @param {string} contactLink - The node URL referencing another presence.
   * @returns {Promise.<TODO>}
   */
  addContact(contactLink) {
    // TODO
  }

  /**
   * Removes the contact from the routing table.
   *
   * @param {string} fingerprint - Node fingerprint to remove.
   * @returns {Promise.<TODO>}
   */
  removeContact(contactFingerprint) {
    // TODO
  } 

  /**
   * Creates and negotiates a new cluster. A cluster is a shared log containing 
   * commands that rebuild a shared media timeline state machine. This 
   * abstraction may be surfaced as a personal journal, a public blog, a group 
   * chat, a virtual filesystem, etc etc.
   *
   * 
   */
  createCluster() {
    // TODO
  }

  /**
   * Destroys a cluster. Removes all local traces of the shared timeline.
   *
   *
   */
  destroyCluster() {
    // TODO
  }

  /**
   * Replays the cluster log associated with the given identifier from the 
   * readable end.
   * Appends the command payload to the log of the specified cluster on the 
   * writable end.
   *
   * @param {string} clusterId - The unique UUID v4 assigned to the cluster.
   * @returns {external:Readable.<external:LogEntry>} 
   */
  createDuplexTimeline(clusterId) {
    const { cluster } = this.clusters.get(clusterId);
    const { log } = cluster.state;
    
    let readIndex = 0;

    function getNextLogEntry() {
      return new Promise((resolve) => {
        let entry = log[readIndex++];
        
        if (entry) {
          return resolve(entry);
        }

        cluster.once(events.LogCommit, resolve);
      });
    }

    const dStream = new Duplex({
      async read() {
        this.push(await getNextLogEntry());
      },
      write(data, _enc, writeDidComplete) {
        cluster.broadcast(data);
        writeDidComplete();
      },
      objectMode: true
    });

    return dStream;
  }

  /**
   *
   *
   *
   */
  createControllerInterface() {
    return {
      // TODO
    };
  }

  /**
   * Links a local or remote client with this presence, exposing an API for 
   * userland applications to integrate with damselfish.
   *
   * 
   */
  linkControllerClient(clientPublicKey, serverOpts) {
    const controllerApi = this.createControllerInterface();
    const clientToken = randomBytes(32);
    const clientChallenge = randomBytes(64);

    const controlServer = new Server({}, () => 
      this.tor.createServer());

    let didRegister = typeof clientPublicKey === 'string';

    controlServer.api = didRegister
      ? { challenge, authenticate }
      : { register };

    const register = async (token, _clientPublicKey, respond) => {
      if (token === clientToken.toString('hex')) {
        didRegister = true;
        controlServer.api.register = null;
        controlServer.api = { challenge, authenticate };

        this.clients.add(_clientPublicKey);
        this.emit(Presence.Events.ClientRegistered, {
          clientPublicKey: _clientPublicKey,
          clientToken,
          clientChallenge,
          serverAddress
        });
        respond(null, []);
      } else {
        respond(new Error('Unauthorized.'));
      }
    }

    const challenge = (respond) => {
      respond(null, [this.identity.message(clientPublicKey, {
        challenge: clientChallenge.toString('hex')
      })]);
    };

    function authenticate(decryptedChallenge, respond) {
      if (decryptedChallenge !== clientChallenge.toString('hex')) {
        return respond(new Error('Unauthorized.'));
      }

      for (let method in controllerApi) {
        controlServer.api[method] = controllerApi[method];
      }

      respond(null, Object.keys(controllerApi));
    }

    return new Promise(async (resolve, reject) => {
      let address;

      try {
        address = await controlServer.server.listen(serverOpts);
      } catch (e) {
        return reject(e);
      }

      this._controlServers.set(clientPublicKey, controlServer);
      resolve({ address, token: clientToken });
    });
  }

  /**
   * Unlinks a local or remote client from this presence. 
   *
   * 
   */
  unlinkControllerClient(clientPublicKey) {
    const server = this._controlServers.get(clientPublicKey);

    if (!server) {
      return Promise.reject(new Error('Key not registered.'));
    }

    return new Promise((resolve, reject) => {
      try {
        server.server.close();
      } catch (e) {
        return reject(e);
      }

      this.clients.delete(clientPublicKey);
      this.emit(Presence.Events.ClientUnregistered, clientPublicKey);
      
      resolve();
    });
  }

}

module.exports.Presence = Presence;
