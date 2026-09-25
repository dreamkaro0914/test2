'use strict';

// 依存ライブラリなしの、追記型JSONストア。
// - images.json : 画像メタデータ
// - visits.json : アクセスログ（匿名化済み）
const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');

function ensure() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  for (const f of ['images.json', 'visits.json']) {
    const p = path.join(DATA_DIR, f);
    if (!fs.existsSync(p)) fs.writeFileSync(p, '[]');
  }
}

function read(name) {
  ensure();
  try {
    return JSON.parse(fs.readFileSync(path.join(DATA_DIR, name), 'utf8') || '[]');
  } catch {
    return [];
  }
}

function write(name, arr) {
  ensure();
  fs.writeFileSync(path.join(DATA_DIR, name), JSON.stringify(arr, null, 2));
}

const Images = {
  all: () => read('images.json'),
  add(meta) {
    const arr = read('images.json');
    arr.unshift(meta);
    write('images.json', arr);
    return meta;
  },
  get(id) {
    return read('images.json').find((i) => i.id === id) || null;
  },
  remove(id) {
    const arr = read('images.json').filter((i) => i.id !== id);
    write('images.json', arr);
  },
};

const Visits = {
  all: () => read('visits.json'),
  add(entry) {
    const arr = read('visits.json');
    arr.push(entry);
    // 上限を設けて肥大化を防ぐ（直近5000件）。
    if (arr.length > 5000) arr.splice(0, arr.length - 5000);
    write('visits.json', arr);
    return entry;
  },
};

module.exports = { Images, Visits, DATA_DIR, ensure };
