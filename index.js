const dgram = require('dgram')
const { EventEmitterMixin } = require('event-emitter-mixin')
const constants = require('./constants')
const _ = require('lodash')

class FinsClient extends EventEmitterMixin() {
  constructor(port, host, options) {
    super()

    const defaultHost = constants.DefaultHostValues
    const defaultOptions = constants.DefaultOptions

    this.port = port || defaultHost.port
    this.host = host || defaultHost.host
    this.timeout = (options && options.timeout) || defaultOptions.timeout
    this.socket = dgram.createSocket('udp4')
    this.responded = false
    this.header = constants.DefaultFinsHeader
    this.responses = {
      data: {}
    }

    this.socket.on('message', (buf, rinfo) => {
      this.responded = true
      this.emit('reply', this._processReply(buf, rinfo))
    })
    this.socket.on('listening', () => this.emit('open'))
    this.socket.on('close', () => this.emit('close'))
    this.socket.on('error', err => this.emit('error', err))

    if (this.timeout) {
      setTimeout(() => {
        if (this.responded === false) {
          this.emit('timeout', this.host)
        }
      }, this.timeout)
    }
  }

  _mergeArrays(array) {
    return _.flattenDeep(array)
  }

  _keyFromValue(dict, value) {
    return Object.keys(dict).find(key => {
      return dict[key] === value
    })
  }

  _wordsToBytes(words) {
    const bytes = []
    if (!words.length) {
      bytes.push((words & 0xff00) >> 8)
      bytes.push(words & 0x00ff)
    } else {
      for (const i in words) {
        bytes.push((words[i] & 0xff00) >> 8)
        bytes.push(words[i] & 0x00ff)
      }
    }
    return bytes
  }

  _translateMemoryAddress(memoryAddress) {
    const re = /(.)([0-9]*):?([0-9]*)/
    const matches = memoryAddress.match(re)
    const decodedMemory = {
      MemoryArea: matches[1],
      Address: matches[2],
      Bit: matches[3]
    }
    const temp = []
    if (!constants.MemoryAreas[decodedMemory['MemoryArea']]) {
      temp.push([0x82])
    } else {
      temp.push([constants.MemoryAreas[decodedMemory['MemoryArea']]])
    }
    temp.push(this._wordsToBytes([decodedMemory['Address']]))
    temp.push([0x00])
    return this._mergeArrays(temp)
  }

  _incrementSID(sid) {
    return (sid % 254) + 1
  }

  _buildHeader(header) {
    return [
      header.ICF,
      header.RSV,
      header.GCT,
      header.DNA,
      header.DA1,
      header.DA2,
      header.SNA,
      header.SA1,
      header.SA2,
      header.SID
    ]
  }

  _buildPacket(raw) {
    return this._mergeArrays(raw)
  }

  _getResponseType(buf) {
    const response = []
    response.push(buf[10])
    response.push(buf[11])
    return response
  }

  _processDefault(buf, rinfo) {
    const sid = buf[9]
    const command = buf.slice(10, 12).toString('hex')
    const response = buf.slice(12, 14).toString('hex')
    const result = { remotehost: rinfo.address, sid: sid, command, response }
    this.responses.data = { ...this.responses.data, [sid]: result }
    return result
  }

  _processStatusRead(buf, rinfo) {
    const sid = buf[9]
    const command = buf.slice(10, 12).toString('hex')
    const response = buf.slice(12, 14).toString('hex')
    const status = buf[14]
    const mode = buf[15]

    const fatalErrorData = _.reduce(
      constants.FatalErrorData,
      (acc, item, key) => {
        return (buf.readInt16BE(17) & item) !== 0 ? [...acc, key] : acc
      },
      []
    )
    const nonFatalErrorData = _.reduce(
      constants.NonFatalErrorData,
      (acc, item, key) => {
        return (buf.readInt16BE(18) & item) !== 0 ? [...acc, key] : acc
      },
      []
    )
    const statusCodes = constants.Status
    const runModes = constants.Modes

    const result = {
      remotehost: rinfo.address,
      sid: sid,
      command: command,
      response: response,
      status: this._keyFromValue(statusCodes, status),
      mode: this._keyFromValue(runModes, mode),
      fatalErrorData: fatalErrorData || null,
      nonFatalErrorData: nonFatalErrorData || null
    }
    this.responses.data = { ...this.responses.data, [sid]: result }
    return result
  }

  _processMemoryAreaRead(buf, rinfo) {
    const data = []
    const sid = buf[9]
    const command = buf.slice(10, 12).toString('hex')
    const response = buf.slice(12, 14).toString('hex')
    const values = buf.slice(14, buf.length)
    for (let i = 0; i < values.length; i += 2) {
      data.push(values.readInt16BE(i))
    }
    const result = {
      remotehost: rinfo.address,
      sid: sid,
      command,
      response: response,
      values: data
    }
    this.responses.data = { ...this.responses.data, [sid]: result }
    return result
  }

  _processReply(buf, rinfo) {
    const commands = constants.Commands
    const responseType = this._getResponseType(buf).join(' ')

    switch (responseType) {
      case commands.CONTROLLER_STATUS_READ.join(' '):
        return this._processStatusRead(buf, rinfo)
      case commands.MEMORY_AREA_READ.join(' '):
        return this._processMemoryAreaRead(buf, rinfo)
      default:
        return this._processDefault(buf, rinfo)
    }
  }

  _decodePacket(buf, rinfo) {
    const data = []
    const command = buf.slice(10, 12).toString('hex')
    const code = buf.slice(12, 14).toString('hex')
    const values = buf.slice(14, buf.length)
    for (let i = 0; i < values.length; i += 2) {
      data.push(values.readInt16BE(i))
    }
    return {
      remotehost: rinfo.address,
      command: command,
      code: code,
      values: data
    }
  }

  read(address, regsToRead, callback) {
    this.header.SID = this._incrementSID(this.header.SID)
    const header = this._buildHeader(this.header)
    const aAddress = this._translateMemoryAddress(address)
    const aRegsToRead = this._wordsToBytes(regsToRead)
    const command = constants.Commands.MEMORY_AREA_READ
    const commandData = [aAddress, aRegsToRead]
    const packet = this._buildPacket([header, command, commandData])
    const buffer = Buffer.from(packet)
    this.socket.send(
      buffer,
      0,
      buffer.length,
      this.port,
      this.host,
      callback(this.header.SID)
    )
  }

  promiseRead(address, regsToRead) {
    return new Promise((resolve, reject) =>
      this.read(address, regsToRead, sid => (err, bytes) => {
        if (err) reject(err)
        let counter = 5
        const innerInterval = setInterval(() => {
          const response = this.responses.data[sid]
          if (response !== undefined) {
            clearInterval(innerInterval)
            delete this.responses.data[sid]
            return resolve({ address, regsToRead, response })
          } else if (counter <= 0) {
            clearInterval(innerInterval)
            return reject(new Error(`Data not found for ${sid}`))
          }
          counter -= 1
        }, 200)
      })
    )
  }

  write(address, dataToBeWritten, callback) {
    this.header.SID = this._incrementSID(this.header.SID)
    const header = this._buildHeader(this.header)
    const aAddress = this._translateMemoryAddress(address)
    const regsToWrite = this._wordsToBytes(dataToBeWritten.length || 1)
    const command = constants.Commands.MEMORY_AREA_WRITE
    const aDataToBeWritten = this._wordsToBytes(dataToBeWritten)
    const commandData = [aAddress, regsToWrite, aDataToBeWritten]
    const packet = this._buildPacket([header, command, commandData])
    const buffer = Buffer.from(packet)
    this.socket.send(
      buffer,
      0,
      buffer.length,
      this.port,
      this.host,
      callback(this.header.SID)
    )
  }

  promiseWrite(address, dataToBeWritten) {
    return new Promise((resolve, reject) =>
      this.write(address, dataToBeWritten, sid => (err, bytes) => {
        if (err) reject(err)
        let counter = 5
        const innerInterval = setInterval(() => {
          const response = this.responses.data[sid]
          if (response !== undefined) {
            clearInterval(innerInterval)
            delete this.responses.data[sid]
            return resolve({ address, dataToBeWritten, response })
          } else if (counter <= 0) {
            clearInterval(innerInterval)
            return reject(new Error(`Data not write on address ${address}`))
          }
          counter -= 1
        }, 200)
      })
    )
  }

  fill(address, dataToBeWritten, regsToWrite, callback) {
    this.header.SID = this._incrementSID(this.header.SID)
    const header = this._buildHeader(this.header)
    const aAddress = this._translateMemoryAddress(address)
    const aRegsToWrite = this._wordsToBytes(regsToWrite)
    const command = constants.Commands.MEMORY_AREA_FILL
    const aDataToBeWritten = this._wordsToBytes(dataToBeWritten)
    const commandData = [aAddress, aRegsToWrite, aDataToBeWritten]
    const packet = this._buildPacket([header, command, commandData])
    const buffer = Buffer.from(packet)
    this.socket.send(
      buffer,
      0,
      buffer.length,
      this.port,
      this.host,
      callback(this.header.SID)
    )
  }

  promiseFill(address, dataToBeWritten, regsToWrite) {
    return new Promise((resolve, reject) =>
      this.fill(address, dataToBeWritten, regsToWrite, sid => (err, bytes) => {
        if (err) reject(err)
        let counter = 5
        const innerInterval = setInterval(() => {
          const response = this.responses.data[sid]
          if (response !== undefined) {
            clearInterval(innerInterval)
            delete this.responses.data[sid]
            return resolve({ address, dataToBeWritten, response })
          } else if (counter <= 0) {
            clearInterval(innerInterval)
            return reject(
              new Error(
                `Data not fill on address ${address} for ${regsToWrite} regs`
              )
            )
          }
          counter -= 1
        }, 200)
      })
    )
  }

  run(callback) {
    this.header.SID = this._incrementSID(this.header.SID)
    const header = this._buildHeader(this.header)
    const command = constants.Commands.RUN
    const packet = this._buildPacket([header, command])
    const buffer = Buffer.from(packet)
    this.socket.send(
      buffer,
      0,
      buffer.length,
      this.port,
      this.host,
      callback(this.header.SID)
    )
  }

  promiseRun() {
    return new Promise((resolve, reject) =>
      this.run(sid => (err, bytes) => {
        if (err) reject(err)
        let counter = 5
        const innerInterval = setInterval(() => {
          const response = this.responses.data[sid]
          if (response !== undefined) {
            clearInterval(innerInterval)
            delete this.responses.data[sid]
            return resolve({ response })
          } else if (counter <= 0) {
            clearInterval(innerInterval)
            return reject(new Error('Run command response not received'))
          }
          counter -= 1
        }, 200)
      })
    )
  }

  stop(callback) {
    this.header.SID = this._incrementSID(this.header.SID)
    const header = this._buildHeader(this.header)
    const command = constants.Commands.STOP
    const packet = this._buildPacket([header, command])
    const buffer = Buffer.from(packet)
    this.socket.send(
      buffer,
      0,
      buffer.length,
      this.port,
      this.host,
      callback(this.header.SID)
    )
  }

  promiseStop() {
    return new Promise((resolve, reject) =>
      this.stop(sid => (err, bytes) => {
        if (err) reject(err)
        let counter = 5
        const innerInterval = setInterval(() => {
          const response = this.responses.data[sid]
          if (response !== undefined) {
            clearInterval(innerInterval)
            delete this.responses.data[sid]
            return resolve({ response })
          } else if (counter <= 0) {
            clearInterval(innerInterval)
            return reject(new Error('Stop command response not received'))
          }
          counter -= 1
        }, 200)
      })
    )
  }

  status(callback) {
    this.header.SID = this._incrementSID(this.header.SID)
    const header = this._buildHeader(this.header)
    const command = constants.Commands.CONTROLLER_STATUS_READ
    const packet = this._buildPacket([header, command])
    const buffer = Buffer.from(packet)
    this.socket.send(
      buffer,
      0,
      buffer.length,
      this.port,
      this.host,
      callback(this.header.SID)
    )
  }

  promiseStatus() {
    return new Promise((resolve, reject) =>
      this.status(sid => (err, bytes) => {
        if (err) reject(err)
        let counter = 5
        const innerInterval = setInterval(() => {
          const response = this.responses.data[sid]
          if (response !== undefined) {
            clearInterval(innerInterval)
            delete this.responses.data[sid]
            return resolve({ response })
          } else if (counter <= 0) {
            clearInterval(innerInterval)
            return reject(new Error(`Data not found for ${sid}`))
          }
          counter -= 1
        }, 200)
      })
    )
  }

  close() {
    this.socket.close()
  }
}

module.exports.FinsClient = FinsClient
