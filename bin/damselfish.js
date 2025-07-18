#!/usr/bin/env node

'use strict';

const { EventEmitter } = require('node:events');
const { fork } = require('node:child_process');

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
    help: '⸱⸱ℹ️ ⸱⸱'
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
          return clc.bold(text) + ' ~ ';
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
  Collection } = require('../index');

const program = new Command();

program
  .name(clc.bold('fishdb'))
  .description(clc.italic(require('../package.json').description))
  .version(require('../package.json').version);

program
  .command('open')
  .description('load or create a database')
  .argument('[directory]', 'path to database directory', Config.DataDirectory)
  .option('-u, --unlock [password]', 'database decryption passphrase')
  .option('-i, --interactive', 'prompt for user input & open query shell')
  .option('-d, --detach', 'run process in the background')
  .action(async (datadir, options) => {
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

      // TODO 

      if (process.channel) {
        process.send({ debug: text });
        process.disconnect();
      } else {
        loading.stopAndPersist({
          symbol: theme.prefix.done,
          text
        });
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
  });

program
  .command('shell')
  .description('run queries on a damselfish database')
  .argument('[query]', 'optionally run given query and exit')
  .option('-c, --connect <address>', 'anonymously connect to a remote database')
  .option('-u, --unlock [password]', 'authentication key decryption passphrase', '')
  .action(async (fishql, options) => {
    const loading = Spinner({ 
      text: `Loading ${datadir || Config.DataDirectory}...`,
      spinner 
    }).start()
    const config = new Config(datadir);

    // TODO
  });

if (!process.channel) {
  console.log(clc.bold(titleArt));
}

program.parse();


