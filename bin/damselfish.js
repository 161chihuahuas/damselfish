#!/usr/bin/env node

'use strict';

const { EventEmitter } = require('node:events');

const clc = require('cli-color');
const Spinner = require('yocto-spinner').default;

const spinner = {
  frames: ['⸱⸱⸱⸱⸱⸱', '⸱⸱⸱⸱🐠', '⸱⸱🐠🫧', '🐠🫧🫧', '🫧🫧🫧', '🫧🫧⸱⸱', '🫧⸱⸱⸱⸱'],
  interval: 100
};

const { Command } = require('commander');
const { 
  Presence, 
  Config,
  Storage,
  Link,
  Collection } = require('../index');

const program = new Command();

program
  .name(clc.bold('damselfish'))
  .description(clc.italic(require('../package.json').description))
  .version(require('../package.json').version)
  .argument('[database]', 'Load a database or create a new one')
  .option('-u, --unlock <password>', 'Encrypt/decrypt database key', '')
  .action(async (datadir, options) => {
    const loading = Spinner({ 
      text: `Loading ${datadir || Config.DataDirectory}...`,
      spinner 
    }).start()
    const config = new Config(datadir);

    let db = null;

    try {
      db = await Presence.create(config, options.u, loading);
      onPresenceCreated(db);
    } catch (e) {
      return onPresenceError(e);
    }

    function onPresenceCreated(db) {
      loading.success(`${datadir || Config.DataDirectory} loaded!`);
      // TODO
    }

    function onPresenceError(err) {
      loading.error(err);
      process.exit(1);
    }    
  });

program.parse();


