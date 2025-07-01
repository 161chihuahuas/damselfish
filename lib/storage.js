/**
 *
 *
 * @module damselfish/storage
 */

'use strict';

const { statSync, existsSync, mkdirSync } = require('node:fs');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Readable } = require('node:stream');


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

  get(key) {
    return new Promise(async (resolve, reject) => {
      const info = key + '.info';
      
      let data;

      try {
        data = await fs.readFile(path.join(this.root, info));
      } catch (err) {
        return this.emit('error', err);
      }

      const item = JSON.parse(data);
      const key = info.split('.')[0];
      const datafile = path.join(this.root, key + '.part');

      let buffer;

      try {
        buffer = await fs.readFile(datafile);
      } catch (err) {
        return this.emit('error', err);
      }

      item.value = buffer.toString('hex');
      
      resolve(item);
    });
  }

  put(key, item) {
    return new Promise(async (resolve, reject) => {
      let { value, timestamp, publisher } = item;

      const blob = Buffer.from(value, 'hex');
      const info = JSON.stringify({ timestamp, publisher });
      const blobInfoPath = path.join(this.root, key + '.info');
      const blobDataPath = path.join(this.root, key + '.part');

      try {
        await fs.writeFile(blobDataPath, blob);
        await fs.writeFile(blobInfoPath, info);
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
        await fs.unlink(path.join(this.root, key + '.info'));
        await fs.unlink(path.join(this.root, key + '.part'));
      } catch (err) {
        return reject(err);
      }

      resolve();
    });
  }

  createReadStream() {
    const list = fs.readdirSync(this.root).filter((filename) => {
      return path.extname(filename) === '.info';
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
    return fs.existsSync(path.join(this.root, key + '.info')) && 
      fs.existsSync(path.join(this.root, key + '.part'));
  }

}

module.exports.Storage = Storage;
