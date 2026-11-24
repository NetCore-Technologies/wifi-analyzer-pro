
const reduce=matchMedia('(prefers-reduced-motion: reduce)').matches;
const c=document.getElementById('fx'),x=c.getContext('2d');
let W,H,ang=0;
const names=['Home','Cafe','Guest','Office','IoT','Mesh','Hall','Lab','Garage','Hotspot'];
const aps=names.map(n=>({n,a:Math.random()*6.283,r:0.18+Math.random()*0.75,p:0,d:-32-Math.floor(Math.random()*52)}));
function size(){W=c.width=innerWidth;H=c.height=innerHeight}
size();addEventListener('resize',size);
function frame(){
x.clearRect(0,0,W,H);
const cx=W/2,cy=H*0.46,R=Math.min(W,H)*0.46;
x.lineWidth=1;
for(let k=1;k<=4;k++){x.strokeStyle='rgba(0,224,208,0.14)';x.beginPath();x.arc(cx,cy,R*k/4,0,6.283);x.stroke()}
x.strokeStyle='rgba(0,224,208,0.1)';
x.beginPath();x.moveTo(cx-R,cy);x.lineTo(cx+R,cy);x.moveTo(cx,cy-R);x.lineTo(cx,cy+R);x.stroke();
if(x.createConicGradient){const g=x.createConicGradient(ang-1,cx,cy);g.addColorStop(0,'rgba(0,224,208,0)');g.addColorStop(0.158,'rgba(0,224,208,0.38)');g.addColorStop(0.1585,'rgba(0,224,208,0)');g.addColorStop(1,'rgba(0,224,208,0)');x.fillStyle=g;x.beginPath();x.arc(cx,cy,R,0,6.283);x.fill()}
x.strokeStyle='rgba(127,255,243,0.9)';x.lineWidth=2;x.beginPath();x.moveTo(cx,cy);x.lineTo(cx+Math.cos(ang)*R,cy+Math.sin(ang)*R);x.stroke();
x.font='11px ui-monospace,monospace';
for(const a of aps){
const diff=((ang-a.a)%6.283+6.283)%6.283;
if(diff<0.05)a.p=1;
a.p*=0.988;
const px=cx+Math.cos(a.a)*a.r*R,py=cy+Math.sin(a.a)*a.r*R;
x.fillStyle='rgba(0,224,208,'+(0.25+a.p*0.75)+')';
x.beginPath();x.arc(px,py,3+a.p*7,0,6.283);x.fill();
if(a.p>0.1){x.strokeStyle='rgba(0,224,208,'+a.p*0.5+')';x.beginPath();x.arc(px,py,8+(1-a.p)*30,0,6.283);x.stroke();x.fillStyle='rgba(230,251,249,'+a.p+')';x.fillText(a.n+'  '+a.d+' dBm',px+12,py+4)}
}
ang+=0.017;
if(!reduce)requestAnimationFrame(frame)}
frame();
