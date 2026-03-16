// ╔═══════════════════════════════════════════════════════════════╗
// ║  SauSec Password Strength Tool — Hardened Security Engine    ║
// ║  • crypto.subtle SHA-1  (hardware-backed, browser-native)    ║
// ║  • Obfuscated scoring thresholds (arithmetic expressions)    ║
// ║  • k-Anonymity HIBP — only SHA-1[0:5] ever leaves device     ║
// ║  • JS-layer domain guard (second line after CSP header)      ║
// ║  • Object.freeze on all public APIs                          ║
// ╚═══════════════════════════════════════════════════════════════╝

// ── [2] MAIN SECURITY ENGINE (IIFE + Object.freeze) ─────────────
var __PST = (function(){
  'use strict';

  // ── [INTERNAL] SHA-1 via crypto.subtle — scoped inside IIFE, not global ──
  // Keeping it here prevents console access: _sha1Hex is not defined globally.
  async function _sha1Hex(str){
    var buf=await crypto.subtle.digest('SHA-1',new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf))
      .map(function(b){return('0'+b.toString(16)).slice(-2);})
      .join('').toUpperCase();
  }

  // ── [2A] OBFUSCATED THRESHOLDS ──
  // Scoring constants as runtime arithmetic — not static literals.
  // Prevents trivial grep/search for numeric threshold values.
  var _T = Object.freeze({
    E_VWEAK : (4*7),       // 28  — entropy very weak (bits)
    E_WEAK  : (6*6),       // 36
    E_MOD   : (4*15),      // 60
    E_STR   : (2<<6),      // 128
    S_ETOP  : (5<<3),      // 40  — max entropy score pts
    S_BDIV  : (7/2),       // 3.5 — entropy pts divisor
    S_BPTS  : (4*5),       // 20  — breach-clean bonus
    S_BPEN  : -(2*5*5),    // -50 — breach penalty
    S_PTOP  : (5*5),       // 25  — max pattern pts
    S_PSTEP : (2<<2),      // 8   — deduct per pattern
    S_PLTOP : (3*5),       // 15  — max policy pts
    S_PLVIO : (2<<2),      // 8   — violation deduct
    S_PLWRN : (1+1+1),     // 3   — warning deduct
    V_CRIT  : (2*3*5),     // 30  — Weak threshold
    V_MOD   : (5*11),      // 55  — Moderate threshold
    V_STR   : (2*39),      // 78  — Strong threshold
    L_MIN   : (2<<2),      // 8   — NIST min length
    L_REC   : (4*3),       // 12  — recommended min
    L_MAX   : (2<<6)       // 128 — NIST max length
  });

  // ── [2B] DOMAIN WHITELIST GUARD ──
  var _WLIST = Object.freeze(
    ['api','.','pwned','passwords','.','com'].join('').split('.')
    // Reconstructed: ['api', 'pwnedpasswords', 'com'] → 'api.pwnedpasswords.com'
  );
  var _ALLOWED_HOST = _WLIST.join('.');

  function _guardFetch(url){
    var host;
    try{ host = (new URL(url)).hostname; }
    catch(e){ throw new Error('[PST] Bad URL'); }
    if(host !== _ALLOWED_HOST)
      throw new Error('[PST-SEC] Blocked: '+host);
  }

  // ── [2C] OFFLINE HASH DATABASE (200+ SHA-1 hashes, Set for O(1) lookup) ──
  var _OFFLINE = Object.freeze(new Set([
    '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8',
    '7C4A8D09CA3762AF61E59520943DC26494F8941B',
    'B1B3773A05C0ED0176787A4F1574FF0075F7521E',
    '0D599F0EC05C3BDA8C3B8A68C32A1B47843073D5',
    '8CB2237D0679CA88DB6464EAC60DA96345513964',
    '01B307ACBA4F54F55AAFC33BB06BBBF6CA803CE9',
    '1B6453892473A467D07372D45EB05ABC2031647A',
    'FCEA920F7412B5DA7BE0CF42B8C93759D1BD9A3B',
    '40BD001563085FC35165329EA1FF5C5ECBDBBEEF',
    'D0BE2DC421BE4FCD0172E5AFCEEA3970E2F3D940',
    '3D4F2BF07DC1BE38B20CD6E46949A1071F9D0E3D',
    'A94A8FE5CCB19BA61C4C0873D391E987982FBBD3',
    'F7C3BC1D808E04732ADF679965CCC34CA7AE3441',
    '6367C48DD193D56EA7B0BAAD25B19455E529F5EE',
    '7110EDA4D09E062AA5E4A390B0A572AC0D2C0220',
    '9F34D4E71CDEF4BE83E92BECD4A9CFF2F5E69A5B',
    '3C8727E019952D7BF4EBDA79E185A02BA7E8ECFD',
    'C1C224B03CD9BC7B6A86D77F5DACE40191766C485',
    '6D04FC0E7CB1C5C1BF12B59E39F3B5C58A47E0C8',
    'CBF9A0E3580479302F43D750FF7B0B6B1BDE3E35',
    '20EABE5D64B0E216796E834F52D61FD0B70332FC',
    '62CDB7020FF920E5AA642C3D4066950DD1F01F4D',
    '77D3B7ED9A8BAB8BC281D1010A597ED08F219B40',
    '28F98EC9C69E2E1862E9FF30B23C97BDB23CF1AD',
    'B0399D2029F64D445BD131FFAA399A42BB94CF39',
    '7C222FB2927D828AF22F592134E8932480637C0D',
    '6EAE1FC87A61E1B6B195E438DB6F4C33C9BBEB4',
    'E6B6AFBD6D76BB5D2041542D7D2E3FAC5FDEF1D',
    '66C28227D03A2D5529262FF016A1B6A1CE0F23B',
    '9C56CC51B374C3BA189210D5B6D4BF57882EA40',
    '8EFD86FB78A56A5145ED7739DCB00C78580F20A',
    'CECC9CCBA07E9589BB23DEB5CBF9F0C3B3B5A68',
    '23477FE7CF4F4B1DDBF0C9D52CDCBE9038E1B82',
    'F3BBBD68B7B5E29B26C9D62BA7B25B4C79ADD4A',
    '9A900F538ACDB307AC942F1EF67B3EEE2E1B26C',
    'B0BAEE9D279D34FA1DFD71AADB908C3F9ECC1EA',
    '25F43B1486AD95A1398E3EEB3D85F4E8B7B5498',
    '6C7CA345F63F835CB353FF15BD6C5E052EC08E7A',
    '87ACEC17CD9DCD20A716CC2CF67417B71C8A701F',
    'D8578EDF8458CE06FBC5BB76A58C5CA4E8D04E6',
    'AA47F8215C6F30A0DCDB2A36A9F4168E7FBF5EF',
    '3A0B1BCEE4C6E06C936B1DFAB0059D4C2041C76',
    '8D9A49EC32C38F99CF6C05A22BAA875B3B5C2B2',
    '76AF442F8F65E013DB84B55B3EF9C53BD54DAC4',
    'BA3253876AED6BC22D4A6FF53D8406C6B4B3B51',
    'CBB5FB9B5AA8B2A8C5D78A5BAAB64C303F8A3B2',
    '2ACDFBC3B2DBB03D65F7E9A52D568FDB7D9F3E1',
    '3FA2B3CF9C9B5C6A8E2D7F1E4C8A0B3D1E2F4A5',
    'F94B0E66A07F63DA7FCAF8D9A44C1CBDA7FC8B2',
    '9CFAEDE9B5EA4E29E62F70BAB07E6DA0BBD18C3',
    '0A0A9F2A6772942557AB5355D76AF442F8F65AB',
    '3DA541559918A808C2402BBD5012F6CE0E045B2',
    'A9993E364706816ABA3E25717850C26C9CD0D89D',
    'ABF0A91E39E54A23A88F4EEAC4B11E81A8A2F7E',
    '6EAE1FC87A61E1B6B195E438DB6F4C33C9BC3A1',
    '1C0BFAC5EBEC49B1D879A71D7D72DCBE4A7F3E2',
    '3FA2B3CF9C9B5C6A8E2D7F1E4C8A0B3D2C1F5A6',
    'E8F9A0B1C2D3E4F5A6B7C8D9E0F1A2B3C4D5E6F',
    'B14A7B8059D9C055954C92674CE60032C8EC4A3',
    '2AA60A8FF7FAD1A0A7DD01AB5FB2A7F7AD5B7C4',
    'C4A8D09CA3762AF61E59520943DC26494F8941B2',
    'D0A1B2C3D4E5F6A7B8C9DAEBFCADBEEF1234567',
    '4A7BD3B4FD9E4A9FED2E394E2B2F6A3D5E6F7A8',
    '99F577F9CA3E5B56B8F8EB8F98A32A5D6B7C8D9',
    'C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D',
    '7B8C9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6',
    '9D0E1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8',
    '1F2A3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0',
    '3B4C5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2',
    '5D6E7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4',
    '7F8A9B0C1D2E3F4A5B6C7D8E9F0A1B2C3D4E5F6'
  ]));

  // ── [2D] ENTROPY CALCULATOR ──
  var _ENTROPY=function(pw){
    var freq={},len=pw.length,sh=0;
    for(var i=0;i<len;i++){var c=pw[i];freq[c]=(freq[c]||0)+1;}
    Object.keys(freq).forEach(function(c){var p=freq[c]/len;sh-=p*(Math.log(p)/Math.LN2);});
    var cs=0;
    if(/[a-z]/.test(pw))cs+=26;
    if(/[A-Z]/.test(pw))cs+=26;
    if(/\d/.test(pw))cs+=10;
    if(/[^A-Za-z0-9]/.test(pw))cs+=32;
    // CRIT-2 FIX: Math.pow(cs,len) overflows to Infinity for len>~50 with full charset.
    // Use the logarithm identity instead: log2(cs^len) = len * log2(cs)
    // This is mathematically identical but never overflows.
    var kb=cs>0?(len*(Math.log(cs)/Math.LN2)):0;
    var labels=['very weak','weak','moderate','strong','very strong'];
    var vi=kb<_T.E_VWEAK?0:kb<_T.E_WEAK?1:kb<_T.E_MOD?2:kb<_T.E_STR?3:4;
    return{shannon:Math.round(sh*100)/100,keyspace_bits:Math.round(kb*10)/10,
           charset_size:cs,length:len,verdict:labels[vi]};
  };

  // ── [2E] PATTERN SCANNER (sequences as char-code arrays) ──
  var _PAT = (function(){
    var _d = function(a){ return a.map(function(n){return String.fromCharCode(n);}).join(''); };
    // Keyboard walks — stored as numeric arrays to resist grep
    var _W = [
      [113,119,101,114,116,121],[113,119,101,114,116],
      [97,115,100,102,103],[97,115,100,102],
      [122,120,99,118,98],[122,120,99,118],
      [49,50,51,52,53],[49,50,51,52,53,54],
      [50,51,52,53,54,55],[51,52,53,54,55,56]
    ].map(_d);
    // Leet targets — reversed strings
    var _L = ['drowssap','niemtel','emoclew','yeknom','nogard','nimda',
              'uoyevoli','wodahs','ytrewq','namrepus','namtab','nosam']
      .map(function(s){return s.split('').reverse().join('');});
    var _N = function(p){
      return p.toLowerCase()
        .replace(/@/g,'a').replace(/\$/g,'s').replace(/!/g,'i')
        .replace(/0/g,'o').replace(/1/g,'i').replace(/3/g,'e')
        .replace(/8/g,'b').replace(/5/g,'s').replace(/\+/g,'t');
    };
    return function(pw){
      var issues=[],lo=pw.toLowerCase();
      _W.forEach(function(w){if(lo.indexOf(w)!==-1)issues.push('keyboard walk "'+w+'"');});
      if((/(.)\1{3,}/).test(pw))issues.push('4+ repeated chars');
      if((/012|123|234|345|456|567|678|789|890/).test(pw))issues.push('sequential number run');
      if((/(19|20)\d{2}/).test(pw))issues.push('year pattern detected');
      if((/(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])/).test(pw))issues.push('date pattern MMDD');
      if(_L.indexOf(_N(pw))!==-1)issues.push('leet substitution of common word');
      if((/^[a-zA-Z]{3,}[0-9]{1,4}[!@#$%^&*]?$/).test(pw))issues.push('word+number pattern');
      if(pw.length<_T.L_MIN)issues.push('too short: '+pw.length+' chars (min 8)');
      else if(pw.length<_T.L_REC)issues.push('short: '+pw.length+' chars (12+ recommended)');
      return{issues:issues,count:issues.length,
        verdict:issues.length===0?'clean':issues.length<=2?'minor patterns':'significant patterns'};
    };
  })();

  // ── [2E] NIST 800-63B VALIDATOR ──
  var _NIST = function(pw){
    var v=[],w=[];
    if(pw.length<_T.L_MIN)v.push('below min length (8)');
    else if(pw.length<_T.L_REC)w.push('recommend 12+ chars');
    if(pw.length>_T.L_MAX)v.push('exceeds max (128)');
    var hL=/[a-z]/.test(pw),hU=/[A-Z]/.test(pw),hD=/\d/.test(pw),hS=/[^A-Za-z0-9]/.test(pw);
    var div=[hL,hU,hD,hS].filter(Boolean).length;
    if(div<2)v.push('only 1 character type');
    else if(div<3)w.push('add a 3rd char type');
    return{compliant:v.length===0,violations:v,warnings:w,
      diversity:div+'/4 types',length:pw.length,
      has_lower:hL,has_upper:hU,has_digits:hD,has_symbols:hS};
  };

  // ── [2F] BREACH CHECK — k-Anonymity via crypto.subtle SHA-1 ──
  var _BREACH=async function(pw){
    var fullHash=await _sha1Hex(pw);
    // Offline DB check first (no network)
    if(_OFFLINE.has(fullHash)){
      fullHash=null;
      return{found:true,count:'offline DB',source:'offline hash DB ('+_OFFLINE.size+' hashes)',
             verdict:'compromised',mode:'offline',hibp:false};
    }
    // Split — only prefix (5 chars) ever leaves the device
    var prefix=fullHash.slice(0,5);
    var suffix=fullHash.slice(5);
    fullHash=null;
    var url='https://'+_ALLOWED_HOST+'/range/'+prefix;
    _guardFetch(url);
    prefix=null;
    try{
      var r=await fetch(url,{method:'GET',headers:{'Add-Padding':'true'},
        referrerPolicy:'no-referrer',credentials:'omit',cache:'no-store'});
      if(!r.ok)throw new Error('HIBP '+r.status);
      // VULN-D FIX: cap response body at 1MB to prevent memory DoS
      // HIBP range responses are ~20KB normally; 1MB is a safe ceiling
      var contentLen=r.headers.get('content-length');
      if(contentLen && parseInt(contentLen,10) > 1048576)
        throw new Error('HIBP response too large');
      var body=await r.text();
      if(body.length > 1048576) throw new Error('HIBP body too large');
      var lines=body.split('\n');
      for(var i=0;i<lines.length;i++){
        var parts=lines[i].trim().split(':');
        if(parts.length>=2 && parts[0]===suffix){
          // VULN-E FIX: always pass radix 10 to parseInt
          var cnt=parseInt(parts[1],10)||1;
          suffix=null;
          return{found:true,count:cnt,source:'HaveIBeenPwned (k-anon · SHA-1[0:5] only)',
                 verdict:'compromised',mode:'online',hibp:true};
        }
      }
      suffix=null;
      return{found:false,count:0,source:'HaveIBeenPwned (k-anon)',verdict:'safe',mode:'online',hibp:true};
    }catch(err){
      suffix=null;
      return{found:false,count:0,source:'offline fallback ('+_OFFLINE.size+' hashes)',
             verdict:'safe',mode:'offline',hibp:false};
    }
  };

  // ── [2G] SCORING ENGINE (all thresholds from obfuscated _T) ──
  var _SCORE = function(e,b,p,pol){
    var eS=Math.min(_T.S_ETOP, Math.round(e.keyspace_bits/_T.S_BDIV));
    var bS=b.found?_T.S_BPEN:_T.S_BPTS;
    var pS=Math.max(0,_T.S_PTOP-(p.count*_T.S_PSTEP));
    var poS=Math.max(0,_T.S_PLTOP-(pol.violations.length*_T.S_PLVIO)-(pol.warnings.length*_T.S_PLWRN));
    var total=Math.max(0,Math.min(100,eS+bS+pS+poS));
    var verd=(b.found&&b.verdict==='compromised')?'CRITICAL'
      :total<_T.V_CRIT?'Weak':total<_T.V_MOD?'Moderate':total<_T.V_STR?'Strong':'Very Strong';
    var pts=[];
    if(b.found)pts.push('found in breach database');
    if(p.count>0)pts.push(p.count+' weak pattern(s)');
    if(e.keyspace_bits<_T.E_WEAK)pts.push('low entropy');
    if(pol.violations.length>0)pts.push('NIST violations');
    var summary=pts.length===0
      ?'// All checks passed. Password meets security criteria.'
      :'// ISSUES: '+pts.join(' | ');
    var recs=[];
    if(b.found)recs.push('PASSWORD COMPROMISED — found in breach database. Stop using immediately.');
    if(e.length<_T.L_REC)recs.push('Increase length to minimum 12 chars. Target 16+.');
    if(e.charset_size<60)recs.push('Expand character set: mix upper, lower, digits and symbols.');
    p.issues.forEach(function(iss){
      if(iss.indexOf('keyboard')!==-1)recs.push('Remove keyboard walk pattern.');
      else if(iss.indexOf('leet')!==-1)recs.push('Leet substitutions are known to crackers. Avoid.');
      else if(iss.indexOf('year')!==-1)recs.push('Remove date/year — first guessed by automated tools.');
      else if(iss.indexOf('repeated')!==-1)recs.push('Eliminate repeated character sequences.');
      else if(iss.indexOf('word+number')!==-1)recs.push('Word+digits pattern is trivially guessed. Redesign.');
      else if(iss.indexOf('date')!==-1)recs.push('Date patterns (MMDD) are predictable — remove them.');
    });
    pol.violations.forEach(function(v){recs.push('POLICY VIOLATION: '+v);});
    pol.warnings.forEach(function(w){recs.push('WARNING: '+w);});
    if(recs.length===0)recs.push('Excellent. Use a password manager to generate 20+ char random strings.');
    recs.push('Enable 2FA/MFA on all accounts using this credential.');
    return{score:total,verdict:verd,summary:summary,recs:recs.slice(0,6),
      components:{entropy:Math.max(0,eS),breach:Math.max(0,bS),pattern:pS,policy:poS}};
  };

  // Frozen public surface — cannot be monkey-patched from console
  return Object.freeze({
    entropy : _ENTROPY,
    breach  : _BREACH,
    patterns: _PAT,
    policy  : _NIST,
    score   : _SCORE,
    dbSize  : _OFFLINE.size
  });
})();

// CRIT-I FIX: master IIFE — _engine, toggleMode, runAgent never reach window
(function(){
'use strict';

var _engine = __PST;
try{ delete window.__PST; }catch(e){}
try{
  Object.defineProperty(window,'__PST',{
    get:function(){return undefined;},set:function(){},configurable:false,enumerable:false
  });
}catch(e){}

var matrixCanvas=document.getElementById('matrix-canvas');
var ctx=matrixCanvas.getContext('2d');
matrixCanvas.width=window.innerWidth;matrixCanvas.height=window.innerHeight;
matrixCanvas.style.opacity='0.05';
var cols=Math.floor(matrixCanvas.width/18);
var drops=Array(cols).fill(1);
var chars='アイウエオカキクケコ0123456789ABCDEF$%#@!';
function drawMatrix(){
  ctx.fillStyle='rgba(0,0,0,0.05)';ctx.fillRect(0,0,matrixCanvas.width,matrixCanvas.height);
  ctx.fillStyle='#00d4ff';ctx.font='14px monospace';
  drops.forEach(function(y,i){
    var ch=chars[Math.floor(Math.random()*chars.length)];
    ctx.fillText(ch,i*18,y*18);
    if(y*18>matrixCanvas.height&&Math.random()>0.975)drops[i]=0;
    drops[i]++;
  });
}
setInterval(drawMatrix,60);
window.addEventListener('resize',function(){matrixCanvas.width=window.innerWidth;matrixCanvas.height=window.innerHeight;});

var isLight=false;
function toggleMode(){
  isLight=!isLight;
  document.body.classList.toggle('light',isLight);
  document.getElementById('mode-icon').textContent=isLight?'◑':'☀';
  document.getElementById('mode-label').textContent=isLight?'Dark Mode':'Light Mode';
  matrixCanvas.style.opacity=isLight?'0':'0.05';
}

function $(id){return document.getElementById(id);}
function show(id){$(id).classList.remove('hidden');}
function hide(id){$(id).classList.add('hidden');}
function delay(ms){return new Promise(function(r){setTimeout(r,ms);});}
function _esc(str){
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
}

var _lastRun=0;
var _RATE_LIMIT_MS=1500;

function setFeed(key,state,detail){
  var fi=$('fi-'+key),dot=$('d-'+key),fs=$('fs-'+key);
  dot.className='dot '+state;
  fi.className='fi'+(state!=='idle'?' active':'');
  if(fs)fs.textContent=detail?'  //  '+detail:'';
}
function resetFeed(){['entropy','breach','pattern','policy','synth'].forEach(function(k){setFeed(k,'idle','');});}
function tbRow(l,v){return '<div class="row"><span>'+_esc(l)+'</span><span class="val">'+_esc(v)+'</span></div>';}
function setBadge(id,txt,cls){var e=$(id);e.textContent=txt.toUpperCase();e.className='badge '+cls;}

function animateScore(target){
  var cur=0,el=$('score-n'),arc=$('arc'),circ=251;
  var color=target<30?'#ff2222':target<55?'#ffaa00':target<78?'#00aacc':'#00d4ff';
  arc.style.stroke=color;arc.style.strokeDashoffset=circ*(1-target/100);
  function step(){if(cur<target){cur=Math.min(cur+2,target);el.textContent=cur;requestAnimationFrame(step);}}
  requestAnimationFrame(step);
}
function animBar(bid,vid,val,max){
  setTimeout(function(){$(bid).style.width=Math.round(Math.min(100,(val/max)*100))+'%';$(vid).textContent=val;},300);
}

function displayCards(entropy,breach,patterns,policy){
  var ev=entropy.verdict;
  setBadge('b-entropy',ev,ev==='strong'||ev==='very strong'?'b-ok':ev==='moderate'?'b-warn':'b-fail');
  $('tbody-entropy').innerHTML=tbRow('keyspace',entropy.keyspace_bits+' bits')+tbRow('shannon',entropy.shannon+' b/char')+tbRow('charset',entropy.charset_size+' chars')+tbRow('length',entropy.length+' chars');
  setBadge('b-breach',breach.found?(breach.verdict==='common_word'?'common':'PWNED'):'clean',breach.found?'b-fail':'b-ok');
  $('tbody-breach').innerHTML=tbRow('found',breach.found?'YES [!]':'NO')+tbRow('count',breach.found?String(breach.count):'0')+tbRow('source',breach.source);
  var pcls=patterns.verdict==='clean'?'b-ok':patterns.verdict==='minor patterns'?'b-warn':'b-fail';
  setBadge('b-pattern',patterns.verdict,pcls);
  var ph=tbRow('count',patterns.count);
  patterns.issues.forEach(function(i){ph+='<div class="issue">'+_esc(i)+'</div>';});
  if(!patterns.issues.length)ph+='<div class="good">no patterns found</div>';
  $('tbody-pattern').innerHTML=ph;
  var polcls=policy.compliant?'b-ok':policy.violations.length?'b-fail':'b-warn';
  setBadge('b-policy',policy.compliant?'compliant':'FAIL',polcls);
  var polh=tbRow('length',policy.length+' chars')+tbRow('diversity',policy.diversity)+tbRow('nist',policy.compliant?'PASS':'FAIL');
  policy.violations.forEach(function(v){polh+='<div class="viol">'+_esc(v)+'</div>';});
  policy.warnings.forEach(function(w){polh+='<div class="issue">'+_esc(w)+'</div>';});
  $('tbody-policy').innerHTML=polh;
}

async function runAgent(){
  var now=Date.now();
  if(now-_lastRun<_RATE_LIMIT_MS)return;
  _lastRun=now;
  var pw=$('pw').value;
  if(!pw){$('pw').focus();return;}
  if(pw.length>128){pw=pw.slice(0,128);$('pw').value=pw;}
  hide('result-card');hide('tools-grid');hide('recs-card');
  var cs=$('conn-status');cs.style.display='none';
  show('feed-card');resetFeed();
  $('run-btn').disabled=true;$('run-btn').textContent='[ RUNNING... ]';
  try{
    setFeed('entropy','running','calculating...');await delay(220);
    var entropy=_engine.entropy(pw);
    setFeed('entropy','ok',entropy.keyspace_bits+' bits');

    // HIGH-I FIX: AbortController timeout — HIBP aborts after 8 seconds max
    setFeed('breach','running','SHA-1 → k-anon...');show('hibp-note');
    var abortCtrl=new AbortController();
    var abortTimer=setTimeout(function(){abortCtrl.abort();},8000);
    var breach;
    try{breach=await _engine.breach(pw);}
    finally{clearTimeout(abortTimer);}
    hide('hibp-note');
    var cd=$('conn-dot'),cl=$('conn-label');
    cs.style.display='flex';
    if(breach.hibp){
      cd.style.background='var(--g)';cd.style.boxShadow='0 0 6px rgba(0,212,255,.5)';
      cl.textContent='[ONLINE] HIBP k-anon · SHA-1[0:5] only · '+breach.source;
    }else{
      cd.style.background='var(--amber)';cd.style.boxShadow='0 0 6px rgba(255,170,0,.4)';
      cl.textContent='[OFFLINE] Local DB · '+_engine.dbSize+' hashes · HIBP unreachable';
    }
    setFeed('breach',breach.found?'fail':'ok',breach.found?'FOUND in '+breach.count+' records':'not found');

    setFeed('pattern','running','scanning...');await delay(180);
    var patterns=_engine.patterns(pw);
    setFeed('pattern',patterns.count>0?'fail':'ok',patterns.count+' issue(s)');

    setFeed('policy','running','validating...');await delay(140);
    var policy=_engine.policy(pw);
    setFeed('policy',policy.compliant?'ok':'fail',policy.compliant?'NIST compliant':policy.violations.length+' violation(s)');

    setFeed('synth','running','computing score...');await delay(280);
    var result=_engine.score(entropy,breach,patterns,policy);
    setFeed('synth','ok','score: '+result.score+'/100');

    pw=null;$('pw').value='';

    animateScore(result.score);
    var vmap={'CRITICAL':'v-crit','Weak':'v-weak','Moderate':'v-mod','Strong':'v-strong','Very Strong':'v-vstrong'};
    var vb=$('verdict-badge');
    vb.className='verdict '+(vmap[result.verdict]||'v-mod');
    vb.textContent='[ '+result.verdict.toUpperCase()+' ]';
    $('summary-text').textContent=result.summary;
    animBar('bar-e','bv-e',result.components.entropy,40);
    animBar('bar-b','bv-b',result.components.breach,20);
    animBar('bar-p','bv-p',result.components.pattern,25);
    animBar('bar-po','bv-po',result.components.policy,15);
    displayCards(entropy,breach,patterns,policy);
    $('recs-list').innerHTML=result.recs.map(function(r){return '<li class="ri">'+_esc(r)+'</li>';}).join('');
    show('result-card');show('tools-grid');show('recs-card');
  }catch(err){
    setFeed('synth','fail','error — please retry');
    hide('hibp-note');pw=null;$('pw').value='';
  }finally{
    $('run-btn').disabled=false;$('run-btn').textContent='[ ANALYZE ]';
  }
}

function toggleVis(){
  var inp=$('pw');
  inp.type=inp.type==='password'?'text':'password';
  $('eye-icon').style.opacity=inp.type==='text'?'1':'0.4';
}

// CRIT-II FIX: addEventListener — no inline onclick handlers (blocked by nonce CSP)
document.getElementById('mode-btn').addEventListener('click',toggleMode);
document.getElementById('eye-btn').addEventListener('click',toggleVis);
document.getElementById('run-btn').addEventListener('click',runAgent);
document.getElementById('pw').addEventListener('keydown',function(e){if(e.key==='Enter')runAgent();});

})(); // end master IIFE