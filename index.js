/**
 * 🐠 distributed anonymous metadata segment encryption layer for integrated 
 * storage (huh?) 
 *
 * @module damselfish
 */

'use strict';

const { homedir } = require('node:os');
const { join, extname } = require('node:path');
const { randomBytes, randomUUID } = require('node:crypto');
const { URL } = require('node:url');
const { stringify } = require('node:querystring');
const { statSync, existsSync, mkdirSync, readdirSync } = require('node:fs');
const { readFile, writeFile } = require('node:fs/promises');
const { EventEmitter } = require('node:events');
const { Readable } = require('node:stream');

const { Validator } = require('jsonschema');

const { Client, Server } = require('@yipsec/scarf');
const { Identity, Message } = require('@yipsec/rise');
const { TorContext } = require('@yipsec/bulb');
const { ScalingBloomFilter } = require('@yipsec/blossom').bloom;
const { Node, Contact, constants } = require('@yipsec/kdns');
const { consensus, events, log } = require('@yipsec/brig');
const { dag, tree } = require('@yipsec/merked');
const { MerkleTree } = require('@yipsec/merked/lib/tree');


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
      RoutingTable: join(datadir, 'routing_table.encrypted'),
      ControlSocket: join(datadir, 'control.sock')
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
    this.collections = new Map();
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
  static create(config, password = '', _loading) {
    config = config || new Config();

    const _dbg = (msg) => {
      _loading.text = msg;

      if (process.channel) {
        process.send({ debug: msg });
        process.disconnect();
      }
    };

    return new Promise(async (resolve, reject) => {
      // Get an instance of where we are going to store DHT records locally.
      _dbg('Loading encrypted graph from: ' + config.DataDirectory);
      const storage = new Storage(config.DataDirectory);
      
      let identity, tor, address;

      try {
        if (existsSync(config.IdentityKeyPath)) {
          _dbg('Solution key already exists, decrypting it');
          // If there is a file at the config.identity path, try to unlock it.
          identity = await Identity.unlock(password, 
            await readFile(config.IdentityKeyPath));
        } else {
          _dbg('No solution key detected, generating one');
          // Otherwise, generate a new identity
          identity = await Identity.generate(6, 90, 5);
        }
        
        _dbg('Solution key found! Saving it...')
        // Save the generated identity encrypted to disk.
        await writeFile(config.IdentityKeyPath, identity.lock(password))

        _dbg('Establishing a secure context through the Tor network');
        // Bootstrap a Tor context before doing anything else!
        tor = new TorContext();

        process.once('uncaughtException', reject);
        process.once('unhandledRejection', reject);
 
        try {
          await tor.spawnTorChildProcess();
          _dbg('Tor connection established, opening control connection');
          await tor.openControlConnection();
          _dbg('Control connection successful');
        } catch (e) {
          return reject(e);
        }
     
        process.removeListener('uncaughtException', reject);
        process.removeListener('unhandledRejection', reject);
        _dbg('Connected to Tor');
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
        _dbg('Found routing table cache, decrypting it');
        const cachedContactList = Message.fromBuffer(
          await readFile(config.RoutingTable)
        ).decrypt(identity.secret.privateKey).unwrap();

        _dbg('Populating router with cached contacts');
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
        let onion;

        if (existsSync(config.OnionKeyPath)) {
          _dbg('Hidden service key detected, decrypting it');
          onion = Message.fromBuffer(await readFile(config.OnionKeyPath))
            .decrypt(identity.secret.privateKey)
            .unwrap(); 
          _dbg('Decrypted hidden service key')
        } else {
          // Otherwise we will create one...
          onion = null;
        }

        _dbg('Establishing Tor onion service.');
        
        // Bind/create onion service.
        address = await server.server.listen({
          keyType: onion ? onion.privateKey.split(':')[0] : 'NEW',
          keyBlob: onion ? onion.privateKey.split(':')[1] : 'BEST'
        });

        // Encrypt the private key.
        if (!onion) {
          onion = {
            privateKey: server.server.privateKey,
            serviceId: server.server.serviceId
          };

          onion = identity
            .message(identity.secret.publicKey, onion).toBuffer();
        
          // Write the encrypted private key to disk.
          await writeFile(config.OnionKeyPath, onion);
        }
      } catch (e) {
        return reject(e);
      }

      // Update our "return address" information shared with peers, now that 
      // we have an onion address and virtual port.
      contact.address.host = address.host;
      contact.address.port = address.port;

      // We can now establish a Presence on the network.
      const presence = new Presence({
        storage,
        identity,
        tor,
        contact,
        server,
        dht,
        clusters: []
      });

      _dbg('Loading clusters manifest');
      const clustersManifest = existsSync(config.ClustersManifest)
        ? Message.fromBuffer(await readFile(config.ClustersManifest))
          .decrypt(identity.secret.privateKey)
          .unwrap()
        : [];

      // Setup clusters (groups of nodes replicating an encrypted log).
      clustersManifest.forEach(async clusterDef => {
        _dbg('Bootstrapping cluster: ' + clusterDef.localkey);
        await presence.createCluster(clusterDef.members, clusterDef.localkey);  
      });

      _dbg('Loading linked clients');
      let linkedClients = existsSync(config.LinkedClients)
        ? Message.fromBuffer(await readFile(config.LinkedClients))
            .decrypt(identity.secret.privateKey)
            .unwrap()
        : {};

      try {
        for (let publicKey in linkedClients) {
          _dbg('Linking controller client: ' + publicKey);
          await presence.linkControllerClient(publicKey, 
            linkedClients[publicKey], () => tor.createServer());
        }

      _dbg('Linking controller client: ' + 
        Buffer.from(identity.secret.publicKey).toString('base64'));

        await presence.linkControllerClient(presence.identity.secret.publicKey, 
          config.ControlSocket);
      } catch (e) {
        return reject(e);
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
              if (this.storage.has(leaf)) {
                try {
                  resolve(await this.storage.get(leaf).blob);
                  return;
                } catch (err) {
                  // noop
                }
              }

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
   * @returns {Promise}
   */
  addContact(contactLink) {
    const contact = Link.fromString(contactLink).toContact();

    this.dht.router.addContactByNodeId(contact.fingerprint, contact);
    return this.dht.join(contact);
  }

  /**
   * Removes the contact from the routing table.
   *
   * @param {string} fingerprint - Node fingerprint to remove.
   * @returns {Promise}
   */
  removeContact(contactFingerprint) {
    this.dht.router.removeContactByNodeId(contactFingerprint);
    return Promise.resolve();
  } 

  /**
   * Creates and negotiates a new cluster. A cluster is a shared log containing 
   * commands that rebuild a shared media timeline state machine. This 
   * abstraction may be surfaced as a personal journal, a public blog, a group 
   * chat, a virtual filesystem, etc etc.
   *
   * 
   */
  createCluster(members = [], localkey = 'default') {
    if (this.clusters.has(localkey)) {
      return Promise.reject(
        new Error('Cluster with local key "' + localkey + '" already exists.')
      );
    }

    return new Promise(async (resolve, reject) => {
      // The peer list in the configuration is converted into a list of Peer 
      // objects.
      const peers = members.map(fingerprint => {
        return new consensus.Peer(fingerprint, _deliverMsg);
      });

      const _deliverMsg = (id, msg) => {
        let client = this.peers.get(id);
        const contact = this.dht.router.getContactById(id);

        if (!client) {
          client = new Client();

          client.stream.on('connect', () => {
            this.peers.set(id, client);
            client.invoke(msg.constructor.method, [msg]);
          }).on('error', (err) => {
            this.peers.delete(id);
          });

          client.connect(contact.address.port);
        } else {
          client.invoke(msg.constructor.method, [msg]);
        }
      };

      // Create a special key to store cluster config locally.
      localkey = localkey || randomUUID();
      const clusterKey = `.CLUSTER_${localkey}`;

      // Check there is a log file at the given path.
      const logState = this.storage.has(clusterKey)
        // Load it from disk.
        ? log.LogState.deserialize((await storage.get(clusterKey)).blob)
        // Otherwise just create a new one.
        : new log.LogState();

      // Create a cluster context.
      const cluster = new consensus.Cluster(localkey, peers, logState);

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

      this.clusters.set(cluster.id, cluster);
      this.collections.set(localkey, new Collection(cluster, this, localkey));
      resolve(cluster);
    });
  }

  /**
   * Destroys a cluster. Removes all local traces of the shared timeline.
   *
   *
   */
  destroyCluster(localkey) {
    return new Promise(async (resolve, reject) => {
      const clusterKey = `.CLUSTER_${localkey}`;
      const cluster = this.clusters.get(localkey);

      if (!cluster) {
        return reject(new Error('Cluster not found.'));
      }

      this.storage.del(clusterKey)
      cluster.removeAllListeners();

      const cMethods = cluster.createProtocolMapping();
      
      for (let method in cMethods) {
        this.server.api[`CLUSTER_${cluster.id}/${method}`] = null;
      }

      this.clusters.del(localkey);
      this.collections.del(localkey);
      resolve();
    });

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
    const api = {
      // TODO add/remove contacts
      // TODO get info
      // TODO create cluster
      // TODO destroy cluster
    };

    const apiFactory = (localkey = 'default', queryStr, respond) => {
      return async (queryStr, respond) => {
        const collection = this.collections.get(localkey);

        if (!collection) {
          return respond(new Error(`Collection "${localkey}" not found.`));
        }

        let result = null;
        const token = queryStr.substring(0, 1);

        switch (token) {
          case '$':
            try {
              result = await collection.get(queryStr.substring(1));
            } catch (e) {
              return respond(e);
            }
            break;
          case '~':
            try {
              result = await collection.tail(queryStr.substring(1));
            } catch (e) {
              return respond(e);
            }
            break;
          case '+':
            const [blob, index] = queryStr.substring(1).split('/');
            try {
              result = await collection.put(Buffer.from(blob, 'hex'), json 
                ? JSON.parse(index)
                : {});
            } catch (e) {
              return respond(e);
            }
            break;
          case '-':
            try {
              result = await collection.tombstone(queryStr.substring(1));
            } catch (e) {
              return respond(e);
            }
            break;
          case '^':
            const [exp, patch] = queryStr.substring(1).split('/');
            try {
              result = await collection.patch(exp, patch 
                ? JSON.parse(patch)
                : {});
            } catch (e) {
              return respond(e);
            }
            break;
          case '%':
            try {
              let schema = queryStr.substring(1)
                ? JSON.parse(queryStr.substring(1))
                : null;

              if (schema) {
                result = await collection.validate(schema);
              } else {
                result = collection.schema;
              }
            } catch (e) {
              return repond(e);
            }
            break;
          case '&':
            // TODO addPeer
            break;
          case '!':
            // TODO removePeer
            break;
          default:
            return respond(new Error('Invalid token "' + token + '"'));
        }

        respond(null, [result])
      };
    };

    for (let [key, collection] of this.collections.entries()) {
      api[`@${key}`] = (queryStr, respond) => {
        return apiFactory(key)(queryStr, respond);
      };
    }

    return api;
  }

  /**
   * Links a local or remote client with this presence, exposing an API for 
   * userland applications to integrate with damselfish.
   *
   * 
   */
  linkControllerClient(clientPublicKey, serverOpts, createServer) {
    const controllerApi = this.createControllerInterface();
    const clientToken = randomBytes(32);
    const clientChallenge = randomBytes(64);

    const controlServer = new Server({}, createServer);

    let didRegister = typeof clientPublicKey === 'string';

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

    controlServer.api = didRegister
      ? { challenge, authenticate }
      : { register };

    return new Promise(async (resolve, reject) => {
      let address;

      const _done = () => {
        this._controlServers.set(clientPublicKey, controlServer);
        resolve({ address, token: clientToken });
      };
      
      if (typeof serverOpts === 'string') {
        return controlServer.listen(serverOpts, _done);
      }

      try {
        address = await controlServer.server.listen(serverOpts);
      } catch (e) {
        return reject(e);
      }
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


class Collection {

  /**
   *
   *
   * @constructor
   * @param {external:Cluster} cluster - The cluster replicating the log.
   * @param {Presence} presence - Network presence for lookups.
   * @param {string} [shortname='default'] - Local identifier for this collection.
   */
  constructor(cluster, presence, shortname = 'default') {
    this.cluster = cluster;
    this.shortname = shortname;
    this.validator = null;
    this.schema = null;
    this.presence = presence;
  }

  validate(jsonSchema) {
    if (!jsonSchema) {
      this.schema = null;
      this.validator = null;
      return Promise.resolve({});
    }

    return new Promise((resolve, reject) => {
      this.validator = new Validator();
     
      try {
        this.validator.addSchema(jsonSchema);
      } catch (e) {
        return reject(e);
      }

      resolve(jsonSchema);
    });
  }

  /**
   *
   *
   */
  get data() {
    const data = this.cluster.state.log.entries.map(logEntry => {
      return Message.from(logEntry.payload);
    }).map(msg => {
      let meta;

      try {
        meta = msg.decrypt(this.identity.secret.privateKey);
      } catch (e) {
        meta = null;
      }

      return meta;
    }).filter(meta => !!meta).filter(meta => {
      if (this.validator) {
        return this.validator.validate(meta.index).valid;
      }
      return true;
    });

    data.forEach(meta => {
      if (meta.index.__tombstone === true) {
        if (typeof meta.index.__position === 'undefined') {
          return;
        }

        data[meta.index.__position].index = {
          __tombstone: true
        };
      }  
    });

    return data.map(meta => !meta.__tombstone);
  }

  /**
   *
   *
   */
  get(exp) {
    return new Promise(async (resolve, reject) => {
      const { jsonquery } = await import('@jsonquerylang/jsonquery').default;
      
      let results;

      try {
        results = jsonquery(this.data, exp).map(async meta => 
          await this.presence.readGraph(meta.graph));
      } catch (e) {
        return reject(e);
      }

      resolve(results);
    });
  } 

  /**
   *
   *
   *
   */
  put(buffer, index) {
    return new Promise(async (resolve, reject) => {
      let graph;

      if (this.validator) {
        const validatorResult = this.validator.validate(index);

        if (!validatorResult.valid) {
          return reject(validatorResult.errors[0]);
        }
      }

      const filter = new ScalingBloomFilter();
      filter.add(JSON.stringify(index || {}));

      const tree = new MerkleTree([buffer, 
        Buffer.from(JSON.stringify(filter))]);

      const hash = tree.root();

      try {
        graph = await this.presence.writeGraph(buffer, 
          `/${this.presence.identity.fingerprint}/${this.hash}.fish`);
      } catch (e) {
        return reject(e);
      }

      let entries = [];

      try {
        for (let p = 0; p < this.cluster.peers.length; p++) {
          const fingerprint = this.cluster.peers[p].id;
          const pubkey = this.presence.dht.router.getContactById(fingerprint)
            .address.pubkey;

          entries.push(this.presence.identity.message(
            pubkey,
            { graph, index },
            { op: 'put' }
          ));
        }
      } catch (e) {
        return reject(e);
      }
   
      entries.forEach(entry => this.cluster.broadcast(entry));
      resolve(entries);
    });
  }

  /**
   *
   * 
   *
   */
  tombstone(exp) {
    return this.patch(exp, {}, false);
  }

  /**
   *
   *
   *
   */
  patch(exp, json, patch = true) {
    return new Promise(async (resolve, reject) => {
      const { jsonquery } = await import('@jsonquerylang/jsonquery').default;
      const results = jsonquery(this.data, exp)
        .filter(entry => !entry.index.__tombstone);

      const entries = results.map(entry => {
        const logEntryIndex = this.cluster.state.log.entries.indexOf(entry);

        return [
          logEntryIndex, 
          { index: entry.payload.index, ...json }
        ];
      });

      const messages = [];

      try {
        for (let e = 0; e < entries.length; e++) {
          const { __position, index } = entries[e];

          for (let p = 0; p < this.cluster.peers.length; p++) {
            const fingerprint = this.cluster.peers[p].id;
            const pubkey = this.presence.dht.router.getContactById(fingerprint)
              .address.pubkey;

            messages.push(this.presence.identity.message(
              pubkey,
              { 
                graph: null, 
                index: { 
                  __position, 
                  __tombstone: true 
                } 
              },
              { op: 'tombstone'}
            ));
            
            if (patch) {
              messages.push(this.presence.identity.message(
                pubkey,
                { graph, index },
                { op: 'patch' }
              ));
            }
          }
        }
      } catch (e) {
        return reject(e);
      }
   
      messages.forEach(message => this.cluster.broadcast(message));
      resolve(entries);
    });
  }

  /**
   *
   *
   *
   */
  tail(exp) {
    return new Promise(async (resolve, reject) => {
      let result;

      try {
        result = await this.get(exp);
      } catch (e) {
        return reject(e);
      }

      const cluster = this.cluster;
      const cursor = new Readable({
        read() {
          const entry = result.unshift();

          if (entry) {
            return this.push(entry)
          }

          cluster.once(LogCommit, (committed) => {
            this.push(committed);
          });
        }
      });

      resolve(cursor);
    });
  }

}

module.exports.Collection = Collection;
