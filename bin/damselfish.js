#!/usr/bin/env node

'use strict';

const { EventEmitter } = require('node:events');
const { fork } = require('node:child_process');
const { readFile } = require('node:fs/promises');
const { inspect } = require('node:util');

const clc = require('cli-color');
const Spinner = require('ora').default;

const spinner = {
  frames: [
    '⸱⸱⸱⸱⸱⸱', 
    '⸱⸱⸱⸱🐠', 
    '⸱⸱⸱🐠⸱', 
    '⸱⸱🐠⸱⸱', 
    '⸱🐠⸱⸱⸱', 
    '🐠⸱⸱⸱⸱', 
    '⸱⸱⸱⸱⸱⸱' 
  ],
  interval: 75
};

const theme = {
  prefix: { 
    idle: '⸱⸱🫧⸱⸱',
    done: '⸱⸱🐠⸱⸱',
    error: '⸱⸱⛔⸱⸱',
    help: '⸱⸱ℹ️ ⸱⸱',
    result: '⸱⸱🎣⸱⸱'
  },
  spinner,
  style: {
    answer(text) {
      return text; 
    },
    message(text, status) {
      switch (status) {
        case 'idle':
        case 'done':
        case 'loading':
        default:
          return clc.bold(text);
      }
    },
    error(text) {
      return theme.prefix.error + ' ' + clc.bold(text) + ' ~ ';
    },
    help(text) {
      return theme.prefix.help + ' ' + clc.bold(text) + ' ~ ';
    }
  }
};

const titleArt = `                                        
   _ )  _   _ _   _   _   ) _(_ o  _ ( _  
  (_(  (_( ) ) ) (   )_) (    ) ( (   ) ) 
                 _) (_            _)      

         ~  N©! 2025 yipsec  ~
`;

const { Command } = require('commander');
const { 
  Presence, 
  Config,
  Storage,
  Link,
  Collection,
  Client,
  Identity,
  SignedMessage } = require('../index');

const program = new Command();

program
  .name(clc.bold('ddb'))
  .description(clc.italic(require('../package.json').description))
  .version(require('../package.json').version)
  .addHelpText('beforeAll', titleArt);  

program
  .command('keygen')
  .description('generate a new identity bundle')
  .option('-l, --lock [password]', 'encrypt the bundle using the supplied password', '')
  .option('-i, --interactive', 'prompt for user input')
  .option('--raw', 'output raw bytes to stdio for piping to other programs')
  .option('--easy', 'use a lowered difficulty setting (!warning!)')
  .action(keygen);

async function keygen(options) {
  const loading = options.raw ? null : Spinner({ 
    text: `Generating a new identity key bundle...`,
    spinner,
    discardStdin: false
  });

  process.on('uncaughtException', e => {
    loading.stopAndPersist({
      text: e.message,
      symbol: theme.prefix.error
    })
  });
  
  const { password } = await import('@inquirer/prompts');

  let _pass = options.lock || '';

  if (_pass === true && options.interactive) {
    _pass = await password({ 
      message: 'Enter passphrase for new identity bundle:',
      mask: true,
      theme
    });
  } 

  loading.start();

  let bundle;

  try {
    if (options.easy) {
      bundle = await Identity.generate(Identity.TEST_Z, Identity.TEST_N, 
        Identity.TEST_K, Identity.TEST_MAGIC);
    } else {
      bundle = await Identity.generate();
    }
  } catch (e) {
    if (options.raw) {
      return process.stderr.write(e.message);
    }
    return loading.fail(e.message);
  }

  if (!options.raw) {
    loading.succeed(inspect([
      bundle.toJSON(), 
      bundle.lock(_pass).toString('base64') 
    ], false, null, true));
  } else {
    process.stdout.write(bundle.lock(_pass));
  }
}

program
  .command('open')
  .description('load or create a database')
  .argument('[directory]', 'path to database directory', Config.DataDirectory)
  .option('-u, --unlock [password]', 'database decryption passphrase')
  .option('-i, --interactive', 'prompt for user input & open query shell')
  .option('-d, --detach', 'run process in the background')
  .action(open);

async function open(datadir, options) {
  const { password } = await import('@inquirer/prompts');

  let _pass = options.unlock || '';

  if (_pass === true && options.interactive) {
    _pass = await password({ 
      message: `Enter passphrase for ${datadir}`,
      mask: true,
      validate: (pass) => {
        return true;
      },
      theme
    });
  } 

  const loading = Spinner({ 
    text: `Loading ${datadir || Config.DataDirectory}...`,
    spinner,
    discardStdin: false
  }).start();

  process.on('uncaughtException', e => {
    loading.stopAndPersist({
      text: e.message,
      symbol: theme.prefix.error
    })
  });

  if (options.detach) {
    loading.text = `Opening ${datadir} in the background`;
    
    const cProc = fork(__filename, [
      'open', datadir, 
      '--unlock', _pass
    ], {
      detached: false,
      sient: true
    });

    cProc.on('error', err => loading.error(err));
    cProc.on('message', msg => {
      if (msg.error) {
        loading.error(msg.error.message);
        loading.stop();
        process.exit(1);
      } else if (msg.debug) {
        loading.text = msg.debug;
      } else {
        loading.text = msg;
      }
    });
    cProc.on('disconnect', () => {
      loading.stop(`${datadir} opened in background`);
      process.exit(0);
    });
    cProc.on('exit', (code) => {
      loading.error('Exited with code ' + code);
    });
    return;
  }

  const config = new Config(datadir);

  Presence.create(config, _pass, loading)
    .then(onPresenceCreated, onPresenceError);

  async function onPresenceCreated(db) {
    const text = `Opened damselfish database: ${datadir || Config.DataDirectory}`; 

    if (process.channel) {
      process.send({ debug: text });
      process.disconnect();
    } else {
      loading.stopAndPersist({
        symbol: theme.prefix.result,
        text
      });

      if (options.interactive) {
        shell(undefined, {
          connect: config.ControlSocket,
          unlock: _pass,
          auth: config.IdentityKeyPath
        }); 
      } 
    }
  }

  function onPresenceError(err) {
    let text = err.message;

    if (err.code === 'EADDRINUSE') {
      text += ' (is damselfish already running?)'
    }

    loading.stopAndPersist({
      symbol: theme.prefix.error,
      text
    });

    if (process.channel) {
      process.send({ error: err });
      process.disconnect();
    }
    
    process.exit(1);
  }    
};

program
  .command('shell')
  .description('run queries on a damselfish database')
  .argument('[query]', 'optionally run given query and exit')
  .option('-c, --connect <address>', 'connect to a custom control socket')
  .option('-r, --remote', 'connect via tor onion connection')
  .option('-u, --unlock [password]', 'authentication key decryption passphrase', '')
  .option('-a, --auth <private key path>', '', Config.createDefaults(
    Config.DataDirectory).IdentityKeyPath)
  .action(shell);

async function shell(query, options) {
  let host = options.connect
    ? options.remote ? Link.fromString(options.connect) : options.connect
    : Config.createDefaults(Config.DataDirectory).ControlSocket;

  let loading, _loader;

  if (!query) {
    loading = Spinner({ 
      text: `Connecting to ${host} with key: ${options.auth}...`,
      spinner 
    }).start();
  }

  const { input, search, password, Separator } = 
    await import('@inquirer/prompts');

  let _pass = options.unlock || '';

  if (_pass === true) {
    _pass = await password({ 
      message: `Enter passphrase for ${options.auth}`,
      mask: true,
      validate: (pass) => {
        return true;
      },
      theme
    });
  } 
  const identity = await Identity.unlock(_pass, 
    await readFile(options.auth));
  const createConnection = options.remote
    ? (await TorContext.create()).createConnection
    : undefined;
  const client = new Client(createConnection);

  if (!query) {
    _loader = Spinner({ 
      text: clc.italic(query),
      spinner 
    });
  }

  function _err(e) {
    !query && loading.stopAndPersist({
      symbol: theme.prefix.error,
      text: e.message
    });
    query && process.stderr.write(e.message + '\n');
    client.stream.destroy();
    process.exit(1);
  }

  function _close() {
    !query && loading.stopAndPersist({
      symbol: theme.prefix.error,
      text: 'Connection closed.'
    });
    query && process.stderr.write({ message: 'Connection closed.' });
    client.stream.destroy();
    process.exit(0)
  }

  function _connect() {
    !query && loading.stopAndPersist({
      symbol: theme.prefix.help,
      text: 'Welcome to the FishQL shell. ' +
        `Type ${clc.bold('help')} or ${clc.bold('?')} to get started <3`
    });

    client.invoke('knock', [], (err, results) => {
      if (err) {
        return _err(err);
      }

      let msg = new SignedMessage(results[0].head.solution, results[0].body, 
        results[0].head);
      const { challenge: decryptedChallenge } = msg
        .decrypt(identity.secret.privateKey).unwrap();

      client.invoke('login', [decryptedChallenge], (err) => {
        if (err) {
          return _err(err);
        }

        _shell();
      });
    })
  }

  function _formatResults(method, results) {
    return inspect(results, false, null, true);
  }

  const _done = (err, results, method) => {
    if (err) {
      if (query) {
        process.stderr.write(JSON.stringify(err) + '\n');
      } else {
        _loader.stopAndPersist({
          symbol: theme.prefix.error,
          text: err.message
        });
      }
    } else {
      switch (method) {
        case 'knock':
          let msg = new SignedMessage(results[0].head.solution, results[0].body, 
            results[0].head);

          results[0] = {
            token: msg.decrypt(identity.secret.privateKey).unwrap().challenge
          };
          break;
        default:
          // noop
      }

      if (query) {
        process.stdout.write(JSON.stringify(results) + '\n');
      } else {
        _loader.stopAndPersist({
          symbol: theme.prefix.result,
          text: _formatResults(method, results)
        });
      }
    }
    if (query) {
      client.stream.destroy()
      process.exit(err ? 1 : 0);
    } else {
      _shell();
    }
  }

  async function _shell() {
    let _input, params = [];
     
    function _getMethods() {
      return new Promise((resolve, reject) => {
        client.invoke('help', [], (err, _methods) => {
          if (err) {
            reject(err);
          } else { 
            resolve(_methods);
          }
        });
      });
    }

    if (query) {
      let [method, ...params] = query.split(' ');
      _input = {
        method,
        params
      };
    }
    
    try {
      _input = _input || await search({
        message: '~ $ ',
        source: async (_input, { signal }) => {
          const methods = [
            {
              name: 'exit',
              value: { method: 'exit', params: [] },
              description: 'Close the FishQL shell',
              short: 'exit()'
            }
          ].concat(await _getMethods()).filter(m => m.name[0] !== '_');

          return _input 
            ? methods.filter(m => m.name.includes(_input))
            : methods;
        },
        pageSize: 9,
        theme,
        validate(_input) {
          return true;
        }
      });
    } catch (e) {
      return _err(e);
    }

    switch (_input.method) {
      case 'exit':
        _close();
        break;
      default:
        for (let p = 0; p < _input.params.length; p++) {
          let [_name, _default] = _input.params[p].split('=').map(s => s.trim())
          _default = _default.replace(/["'"]+/g, '');
          try {
            params.push(query ? _default : await input({
              message: _name + ' =',
              required: true,
              theme,
              default: _default
            }));
          } catch (e) {
            return _err(e);
          }
        }

        _loader && _loader.start(); 
        client.invoke(_input.method, params, (err, results) => {
          _done(err, results, _input.method);
        });
    }
  }

  client.connect(host);
  client.stream
    .on('connect', _connect)
    .on('close', _close)
    .on('error', _err);
}

program.parse();


