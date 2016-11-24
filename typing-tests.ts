/*
 * Tests the defined typings for the module. This code is not intended to make
 * sense as an actual executable program; instead, it tests that common use
 * cases of the library compile without typing errors and that the correct
 * types are inferred where necessary.
 */

/// <reference types="node" />
import dgram = require('dgram');
import packet = require('./index');

let socket = dgram.createSocket('udp4');

let nameQueryPacket: packet.Packet = {
    type: 'query',
    id: 1,
    flags: packet.RECURSION_DESIRED,
    questions: [{
        type: 'A',
        name: 'google.com'
    }]
};

let srvQueryPacket: packet.Packet = {
    type: 'query',
    id: 2,
    questions: [{
        type: 'SRV',
        name: 'testing.local'
    }]
};

let encoded = packet.encode(nameQueryPacket);
let decoded = packet.decode(encoded);

let nameQueryLength = packet.encodingLength(nameQueryPacket);
let srvQueryLength = packet.encodingLength(srvQueryPacket);
let buf = new Buffer(nameQueryLength + srvQueryLength);

packet.encode(nameQueryPacket, buf);
packet.encode(srvQueryPacket, buf, nameQueryLength);

let decoded2 = packet.decode(buf, nameQueryLength);

//
// ensure the appropriate types match:
//

let aAnswer: packet.StringAnswer = {
    type: 'A',
    name: 'www.google.com',
    data: '216.58.193.196'
};

let aaaaAnswer: packet.StringAnswer = {
    type: 'AAAA',
    name: 'www.google.com',
    data: '2607:f8b0:4007:80b::2004'
};

let hinfoAnswer: packet.HInfoAnswer = {
    type: 'HINFO',
    name: 'test.local',
    data: {
        cpu: 'x86',
        os: 'Linux'
    }
};

let nullAnswer: packet.BufferAnswer = {
    type: 'NULL',
    name: 'www.example.com',
    data: new Buffer('null')
};

let ptrAnswer: packet.StringAnswer = {
    type: 'PTR',
    name: '192.168.1.20',
    data: 'test.local'
};

let srvAnswer: packet.SrvAnswer = {
    type: 'SRV',
    name: 'test.local',
    ttl: 300,
    data: {
        port: 80,
        target: '192.168.1.20'
    }
};

let txtAnswer: packet.BufferAnswer = {
    type: 'TXT',
    name: 'www.google.com',
    data: new Buffer('253961548-4297453')
};

let dnameAnswer = {
    type: 'DNAME',
    name: 'www.example.com',
    data: 'www.example.net'
};

let answer: packet.Answer = decoded.answers![0];

// It should be possible to determine what the type of the data contained in
// answer is by inspecting the type field.
switch (answer.type) {
    case 'A':
        let ip: string = answer.data;
        break;
    case 'AAAA':
        let ipv6: string = answer.data;
        break;
    case 'CNAME':
        let cnameData: string = answer.data;
        break;
    case 'DNAME':
        let dnameData: string = answer.data;
        break;
    case 'HINFO':
        let hinfoValue: packet.HInfoData = answer.data;
        break;
    case 'PTR':
        let ptrData: string = answer.data;
        break;
    case 'SRV':
        let srvValue: packet.SrvData = answer.data;
        break;
    default:
        let otherData: Buffer = answer.data;
};
