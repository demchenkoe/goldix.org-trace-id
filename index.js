

const base34 = require('base-x')('1234567890ABCDEFGHJKLMNPQRSTUVWXYZ');

/**
 * - 41 TS (время, 41 год идентификаторов c точностью до миллисекунды с пользовательской эпохой, эпоха от 1 января 2018)
 * - 12 Random Int (дополнительное рандомное число в диапазоне 0-4095)
 * - 1 Flag (0 - IPv4, 1 - UserID)
 * - 32 UserIP или UserID
 *
 */

class TraceID {
  constructor(strOrObj) {
    this._totalBytes = Math.ceil(this.mask.length/8);
    this._epochStart = 0x160AF049000; //1 января 2018
    this._values = {
      id: null,
      random: null,
      isUserId: null,
      ts: null,
    };
    if(strOrObj && typeof strOrObj === 'string') {
      this.setTraceID(strOrObj);
    }
    if(strOrObj && typeof strOrObj === 'object') {
      if(strOrObj.hasOwnProperty('userID')) {
        this.userID = strOrObj.userID;
      } else if(strOrObj.hasOwnProperty('userIP')) {
        this.userIP = strOrObj.userIP;
      }
      if(strOrObj.hasOwnProperty('ts')) {
        this.ts = strOrObj.ts;
      } else {
        this.ts = Date.now();
      }
      if(strOrObj.hasOwnProperty('random')) {
        this.random = strOrObj.random & this.ranges['R'].maxValue;
      } else {
        this.random = utils.randomInt(0, this.ranges['R'].maxValue);
      }
    }
  }
  
  _packToBuffer() {
    let bitStr = [], value;
    for(let i=0; i< this.mask.length; i++) {
      bitStr.push(this.mask[i]);
    }
    
    //заполняем bitStr значениями в соответствии с маской
    for(let symbol in this.ranges) {
      let range = this.ranges[symbol];
      value = typeof this._values[range.field] === 'number' ?  this._values[range.field] : 0;
      value = value.toString(2);
      //Если значение меньше по длине, то в начало подставляем нули
      while(value.length < range.length) {
        value = '0'+value;
      }
      //Заполняем bitStr текущим значением.
      for(let i=0; i<range.length; i++) {
        bitStr[range.startAt+i] =  value[i];
      }
    }
    bitStr = bitStr.join('');
    
    //раскладываем биты в буфер
    let buff = Buffer.alloc( this._totalBytes, 0);
    for(let i=0; i< this._totalBytes; i++) {
      let byteBitStr = bitStr.substr(i*8, 8);
      while (byteBitStr.length < 8) {
        byteBitStr+= '0';
      }
      buff[i] = parseInt(byteBitStr, 2);
    }
    return buff;
  }
  
  _unpackFromBuffer(buff) {
    //формируем bitStr из буфера
    let bitStr = '';
    for(let i=0; i< this._totalBytes; i++) {
      //извлекаем значение байт, заполняя недостающие значения нулями
      bitStr+= ('00000000' + buff[i].toString(2)).substr(-8);
    }
    bitStr=bitStr.substr(0, this.mask.length);
    
    //выставляем значения полей
    for(let symbol in this.ranges) {
      let range = this.ranges[symbol];
      this._values[range.field] = parseInt(bitStr.substr(range.startAt, range.length), 2);
    }
  }
  
  setTraceID(str) {
    this._unpackFromBuffer(
      base34.decode(str.replace(/-/g, ''))
    );
  }
  
  toString() {
    let str = base34.encode(
      this._packToBuffer()
    );
    if(this.hashSplitter) {
      str = str.replace(/(\w)(?=(\w\w\w\w\w)+([^\w]|$))/g, '$1' + this.hashSplitter);
    }
    return str;
  }
  
  get ts() {
    return this._values.ts + this._epochStart;
  }
  
  set ts(v) {
    this._values.ts = v - this._epochStart;
  }
  
  set random(v) {
    this._values.random = v;
  }
  
  get random() {
    return this._values.random;
  }
  
  get isUserId() {
    return this._values.isUserId;
  }
  
  set isUserId(v) {
    this._values.isUserId = v ? 1 : 0;
  }
  
  get id() {
    return this._values.id;
  }
  
  set id(v) {
    return this._values.id = v;
  }
  
  get userID() {
    return this.isUserId === 1 ? this.id : null;
  }
  
  set userID(v) {
    this.isUserId = 1;
    this.id = v;
  }
  
  
  _ipToInt(ip) {
    if (!ip || !this.regexIP.test(ip)) {
      throw new Error('E_INVALID_IP');
    }
    return ip.split('.').map((octet, index, array) => {
      return parseInt(octet, 10) * Math.pow(256, (array.length - index - 1));
    }).reduce((prev, curr) => {
      return prev + curr;
    });
  }
  
  _intToIp(value) {
    if (!value) {
      throw new Error('E_UNDEFINED_INTEGER');
    }
    
    const result = /\d+/.exec(value);
    
    if (!result) {
      throw new Error('E_INTEGER_NOT_FOUND');
    }
    
    value = result[0];
    
    return [
      (value>>24)&0xff,
      (value>>16)&0xff,
      (value>>8)&0xff,
      value&0xff
    ].join('.');
  }
  
  get userIP() {
    return this.isUserId === 0 ? this._intToIp(this.id) : null;
  }
  
  set userIP(v) {
    this.isUserId = 0;
    this.id = this._ipToInt(v);
  }
}

TraceID.prototype.regexIP = /\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/;
TraceID.prototype.hashSplitter = '-'; //трейс айди будет сгруппирован по 5 символов и разделен этим символом
TraceID.prototype.mask = 'TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTRRRRRRRRRRRRFIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII00';
TraceID.prototype.maskSymbolToField = {
  T: 'ts',
  R: 'random',
  F: 'isUserId',
  I: 'id',
};

TraceID.prototype.ranges = {};

for(let i=0; i< TraceID.prototype.mask.length; i++) {
  let symbol = TraceID.prototype.mask[i];
  if(symbol === '0' || symbol=== '1') continue;
  let range = TraceID.prototype.ranges[symbol]
    || (TraceID.prototype.ranges[symbol] = {
      length: 0,
      field: TraceID.prototype.maskSymbolToField[symbol],
      startAt: i
    });
  range.length++;
}

for(let symbol in TraceID.prototype.ranges) {
  let range = TraceID.prototype.ranges[symbol];
  let bits = '';
  while(bits.length < range.length) bits+= '1';
  range.maxValue = parseInt(bits, 2);
}

module.exports.TraceID = TraceID;