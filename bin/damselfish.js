#!/usr/bin/env node

'use strict';

const { EventEmitter } = require('node:events');
const { fork } = require('node:child_process');

const clc = require('cli-color');
const Spinner = require('yocto-spinner').default;

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
    done: '⸱⸱🐠⸱⸱'
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
      return '⛔ ' + clc.bold(text);
    },
    help(text) {
      return 'ℹ️ ' + clc.bold(text);
    }
  }
};

const titleArt = `                                        
   _ )  _   _ _   _   _   ) _(_ o  _ ( _  
  (_(  (_( ) ) ) (   )_) (    ) ( (   ) ) 
                 _) (_            _)      

    N©! 2025 yipsec, always antifascist
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
      spinner 
    }).start();

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
        loading.success(`${datadir} opened in background`);
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
      const text = `${datadir || Config.DataDirectory} loaded!`;

      if (process.channel) {
        process.send({ debug: text });
        process.disconnect();
      } else {
        loading.success(text);
      }
    }

    function onPresenceError(err) {
      loading.error(err.message);
      loading.stop();

      if (process.channel) {
        process.send({ error: err });
        process.disconnect();
      }
      
      process.exit(1);
    }    
  });

program
  .command('query')
  .description('execute a database query')
  .argument('[fishql]', 'quoted fishql query string')
  .option('-c, --connect <address>', 'anonymously connect to a remote database')
  .option('-u, --unlock [password]', 'database decryption passphrase', '')
  .option('-i, --interactive', 'open interactive fishql shell')
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


