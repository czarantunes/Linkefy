

const WA='5548988000996';
const waText=encodeURIComponent('Olá! Vi o site da Linkefy e gostaria de conversar sobre um projeto.');
document.querySelectorAll('.js-wa').forEach(a=>{a.href=`https://wa.me/${WA}?text=${waText}`;a.target='_blank';a.rel='noopener noreferrer'});
// reveal
const io=new IntersectionObserver(es=>es.forEach(e=>{if(e.target.classList.contains('scroll-build-item'))return;e.target.classList.toggle('in',e.isIntersecting)}),{threshold:.12});document.querySelectorAll('.reveal').forEach(el=>io.observe(el));
// cursor
const cursor=document.getElementById('cursor');if(matchMedia('(pointer:fine)').matches){addEventListener('mousemove',e=>{cursor.style.left=e.clientX+'px';cursor.style.top=e.clientY+'px'});document.querySelectorAll('a,button,.feature-card,.service-card,.project-card').forEach(el=>{el.addEventListener('mouseenter',()=>cursor.classList.add('big'));el.addEventListener('mouseleave',()=>cursor.classList.remove('big'))})}else cursor.remove();
// practice accordion
const acc=document.querySelectorAll('.acc-item');const visTitle=document.getElementById('visualTitle'),visIndex=document.getElementById('visualIndex'),visImage=document.getElementById('serviceVisualImage'),visShell=document.getElementById('serviceVisual');acc.forEach((item,i)=>item.querySelector('.acc-head').addEventListener('click',()=>{acc.forEach(x=>{x.classList.remove('active');x.querySelector('.acc-toggle').textContent='+'});item.classList.add('active');item.querySelector('.acc-toggle').textContent='−';visTitle.textContent=item.querySelector('strong').textContent;visIndex.textContent=String(i+1).padStart(2,'0')+' · SERVIÇO';const next=item.dataset.image;if(visImage&&next&&visImage.getAttribute('src')!==next){if(visShell)visShell.classList.add('is-switching');window.setTimeout(()=>{visImage.src=next;visImage.alt=item.querySelector('strong').textContent;if(visShell)visShell.classList.remove('is-switching')},180)}}));
// before / after scroll
const shell=document.getElementById('sec08'),sticky=document.getElementById('baSticky'),before=document.getElementById('baBefore'),after=document.getElementById('baAfter'),notebook=document.getElementById('baNotebook'),baImgBefore=document.getElementById('baImgBefore'),baImgAfter=document.getElementById('baImgAfter');
function baUpdate(){if(!shell)return;const r=shell.getBoundingClientRect(),range=Math.max(1,shell.offsetHeight-innerHeight);let p=Math.max(0,Math.min(1,-r.top/range));const mobileBA=innerWidth<=760;const q=Math.max(0,Math.min(1,mobileBA?((p-.08)/.84):((p-.28)/.45)));sticky.style.background=`rgb(${Math.round(242*(1-q)+7*q)},${Math.round(242*(1-q)+7*q)},${Math.round(242*(1-q)+7*q)})`;before.style.opacity=1-q;before.style.transform=`translateY(${-28*q}px)`;after.style.opacity=q;after.style.transform=`translateY(${30*(1-q)}px)`;notebook.style.transform=`scale(${.84+.16*q}) translateY(${35*(1-q)}px) rotateX(${3*(1-q)}deg)`;if(baImgBefore){baImgBefore.style.opacity=1-q;baImgBefore.style.transform=`scale(${1+.025*q})`}if(baImgAfter){baImgAfter.style.opacity=q;baImgAfter.style.transform=`scale(${1.02-.02*q})`}}
addEventListener('scroll',baUpdate,{passive:true});addEventListener('resize',baUpdate);baUpdate();
// floating CTA
const float=document.getElementById('floatCta'),hero=document.getElementById('inicio'),final=document.getElementById('sec09');function floatUpdate(){const y=scrollY;const heroEnd=hero.offsetHeight*.78;const nearFinal=final.getBoundingClientRect().top<innerHeight*.9;float.classList.toggle('show',y>heroEnd&&!nearFinal)}addEventListener('scroll',floatUpdate,{passive:true});floatUpdate();
// translations
const T={
pt:{},
en:{
'hero.cta':'Start my project','hero.l1':'Digital solutions','hero.l2':'that ','hero.em':'drive','hero.l3':'your business.','hero.desc':'Websites, landing pages, paid traffic and digital solutions that put your business in front of more customers.','hero.clients':'+ Companies that already trust our work.','quote':'Request a quote','sec02.title':'It is not just a beautiful website. It is a structure designed to help you sell more.','sec02.copy':'Whatever your industry, your website needs to create business opportunities.','sec03.a':'Your project starts with one clear commercial goal: generate ','sec03.sales':'sales','sec03.c1t':'Conversion-focused copy','sec03.c1c':'Good looks alone do not sell. The structure needs to lead the customer to action.','sec03.c2t':'Performance and experience','sec03.c2c':'Fast, responsive websites that are easy to use on any screen.','sec03.c3t':'Traffic and acquisition vision','sec03.c3c':'The project is ready for paid traffic and SEO from day one.','sec04.title':'75% of users judge a company’s credibility by the design of its website.','sec04.card1':'More Credibility','sec04.card2':'More Sales','sec05.title':'What we do in practice','sec05.placeholder':'PROJECT IMAGE','sec05.s1t':'Professional Website Creation','sec05.s1c':'We build fast, responsive websites ready for Google. Local SEO, hosting, maintenance, updates and technical support are already part of the delivery.','sec05.s2t':'Landing Pages','sec05.s2c':'Landing pages for campaigns, lead capture and offers with one clear action.','sec05.s3t':'Paid Traffic Management','sec05.s3c':'We plan and manage campaigns to reach the right audience and generate new conversations and sales.','sec05.s4t':'Google Business Profile','sec05.s4c':'We organize and optimize your business profile on Google to improve visibility in local search and Google Maps.','sec05.s7t':'Internal Systems Development','sec05.s7c':'We develop custom internal systems for your operation, including CRM, member areas, sales systems, portals and management dashboards.','full.eyebrow':'OUR SERVICES','full.title':'Complete digital solutions<br>for your business','full.copy':'Websites, paid traffic, Google and internal systems in one place.','full.badge':'MOST POPULAR','full.site.t':'Professional Website Creation','full.site.c':'We build your website from scratch with responsive design, speed, Local SEO and WhatsApp integration. Hosting, maintenance, updates and technical support are part of the project.','full.land.t':'Landing Pages','full.land.c':'Pages built for campaigns, lead capture and sales, with a clear message and one primary action.','full.traffic.t':'Paid Traffic Management','full.traffic.c':'We plan, launch and track campaigns to reach the right audience and generate business opportunities.','full.gmb.t':'Google Business Profile','full.gmb.c':'We set up and optimize your profile to improve visibility in local search and Google Maps.','full.auto.t':'Internal Systems Development','full.auto.c':'We build custom systems to centralize operations, organize customers and turn business processes into proprietary tools.','full.button':'I want this service','full.b1':'A presence that builds trust','full.b2':'More business opportunities','full.b3':'Investment aligned with the project','sec06.title':'Your website is a salesperson that works 24 hours a day, without breaks, commissions or depending on business hours.','sec06.n1':'New sale completed','sec06.now':'just now','sec06.n2':'+R$ 2,480 in sales','sec06.last':'in the last 24 hours','sec07.eyebrow':'PROJECTS','sec07.title':'Projects that impacted businesses.','sec07.copy':'A selection of projects we have already launched for businesses in different industries.','sec07.p1type':'ONLINE STORE','sec07.p1name':'LOA Select','sec07.p1copy':'Online store with a product catalog and checkout through WhatsApp.','sec07.p2type':'DIGITAL MENU','sec07.p2name':'Catafesta ArtCulinária','sec07.p2copy':'Digital menu to organize the catalog and receive orders through WhatsApp.','sec07.p3type':'CORPORATE WEBSITE & BIO LINK','sec07.p3name':'Plenah Clinic','sec07.p3copy':'Corporate website and Bio Link to present the clinic\'s services and bring key links together.','ba.before.t':'No website, no SEO, no sales.','ba.before.c':'When a website feels improvised, the business loses trust, visibility and opportunities.','ba.after.t':'More authority, more customers, more sales.','ba.after.c':'With a professional presence, your business gains authority, makes better use of traffic and makes it easier for new customers to get in touch.','sec09.title':'Right now, a customer may be looking at your competitor’s website instead of yours.','sec09.copy':'Shall we change that?','signature.title':'Talk to Linkefy and turn your digital presence into new opportunities','signature.copy':'Tell us what your business needs. We organize the strategy, build the project and put it live.','signature.button':'Talk to Linkefy','footer.tag':'Websites and landing pages that present your business better and create new opportunities.','footer.contact':'CONTACT','footer.location':'LOCATION'},
es:{
'hero.cta':'Quiero crear mi proyecto','hero.l1':'Soluciones digitales','hero.l2':'que ','hero.em':'impulsan','hero.l3':'tu negocio.','hero.desc':'Sitios, landing pages, tráfico pago y soluciones digitales para poner tu empresa frente a más clientes.','hero.clients':'+ Empresas que ya confían en nuestro trabajo.','quote':'Solicitar presupuesto','sec02.title':'No es solo un sitio bonito, es una estructura pensada para ayudarte a vender más.','sec02.copy':'Sea cual sea tu sector, el sitio necesita generar oportunidades de negocio.','sec03.a':'Tu proyecto nace con un objetivo comercial claro: generar ','sec03.sales':'ventas','sec03.c1t':'Copy enfocado en conversión','sec03.c1c':'Un buen diseño por sí solo no vende. La estructura debe llevar al cliente a la acción.','sec03.c2t':'Rendimiento y experiencia','sec03.c2c':'Sitios rápidos, responsivos y fáciles de usar en cualquier pantalla.','sec03.c3t':'Visión de tráfico y adquisición','sec03.c3c':'El proyecto queda listo para recibir tráfico pago y trabajar el SEO desde el inicio.','sec04.title':'El 75% de los usuarios juzga la credibilidad de una empresa por el diseño de su sitio web.','sec04.card1':'Más Credibilidad','sec04.card2':'Más Ventas','sec05.title':'Lo que hacemos en la práctica','sec05.placeholder':'IMAGEN DEL PROYECTO','sec05.s1t':'Creación de Sitios Profesionales','sec05.s1c':'Creamos sitios rápidos, responsivos y listos para Google. SEO Local, hosting, mantenimiento, actualizaciones y soporte técnico ya forman parte de la entrega.','sec05.s2t':'Landing Pages','sec05.s2c':'Landing pages para campañas, captación de leads y ofertas con una acción clara.','sec05.s3t':'Gestión de Tráfico Pago','sec05.s3c':'Planificamos y gestionamos campañas para llegar al público correcto y generar nuevas conversaciones y ventas.','sec05.s4t':'Google Mi Negocio','sec05.s4c':'Organizamos y optimizamos el perfil de la empresa en Google para mejorar su presencia en búsquedas locales y Google Maps.','sec05.s7t':'Desarrollo de Sistemas Internos','sec05.s7c':'Desarrollamos sistemas internos a medida para tu operación, como CRM, áreas de miembros, sistemas de ventas, portales y paneles de gestión.','full.eyebrow':'NUESTROS SERVICIOS','full.title':'Soluciones digitales completas<br>para tu empresa','full.copy':'Sitios, tráfico pago, Google y sistemas internos reunidos en un solo lugar.','full.badge':'MÁS ELEGIDO','full.site.t':'Creación de Sitios Profesionales','full.site.c':'Creamos tu sitio desde cero, con diseño responsivo, velocidad, SEO Local e integración con WhatsApp. Hosting, mantenimiento, actualizaciones y soporte técnico ya forman parte del proyecto.','full.land.t':'Landing Pages','full.land.c':'Páginas enfocadas en campañas, captación de leads y ventas, con un mensaje claro y una acción principal.','full.traffic.t':'Gestión de Tráfico Pago','full.traffic.c':'Planificamos, publicamos y acompañamos campañas para llegar al público correcto y generar oportunidades comerciales.','full.gmb.t':'Google Mi Negocio','full.gmb.c':'Configuramos y optimizamos tu perfil para mejorar la presencia de la empresa en búsquedas locales y Google Maps.','full.auto.t':'Desarrollo de Sistemas Internos','full.auto.c':'Creamos sistemas a medida para centralizar operaciones, organizar clientes y convertir procesos de la empresa en herramientas propias.','full.button':'Quiero este servicio','full.b1':'Una presencia que transmite confianza','full.b2':'Más oportunidades de negocio','full.b3':'Inversión acorde al proyecto','sec06.title':'Tu sitio es un vendedor que trabaja 24 horas al día, sin pausas, sin comisiones y sin depender del horario comercial.','sec06.n1':'Nueva venta realizada','sec06.now':'ahora mismo','sec06.n2':'+R$ 2.480 en ventas','sec06.last':'en las últimas 24h','sec07.eyebrow':'PROYECTOS','sec07.title':'Proyectos que impactaron negocios.','sec07.copy':'Algunos proyectos que ya pusimos online para negocios de distintos sectores.','sec07.p1type':'TIENDA ONLINE','sec07.p1name':'LOA Select','sec07.p1copy':'Tienda online con catálogo de productos y finalización de compra por WhatsApp.','sec07.p2type':'DIGITAL MENU','sec07.p2name':'Catafesta ArtCulinária','sec07.p2copy':'Menú digital para organizar el catálogo y recibir pedidos por WhatsApp.','sec07.p3type':'SITIO INSTITUCIONAL Y BIO LINK','sec07.p3name':'Plenah Clinic','sec07.p3copy':'Sitio institucional y Bio Link para presentar los servicios de la clínica y reunir los principales accesos.','ba.before.t':'Sin sitio, sin SEO, sin ventas.','ba.before.c':'Cuando un sitio parece improvisado, la empresa pierde confianza, visibilidad y oportunidades.','ba.after.t':'Más autoridad, más clientes, más ventas.','ba.after.c':'Con una presencia profesional, tu empresa gana autoridad, aprovecha mejor el tráfico y facilita el contacto con nuevos clientes.','sec09.title':'En este exacto momento, algún cliente puede estar mirando el sitio de tu competidor y no el tuyo.','sec09.copy':'¿Vamos a cambiar eso?','signature.title':'Habla con Linkefy y transforma tu presencia digital en nuevas oportunidades','signature.copy':'Cuéntanos qué necesita tu empresa. Organizamos la estrategia, desarrollamos el proyecto y lo ponemos online.','signature.button':'Hablar con Linkefy','footer.tag':'Sitios y landing pages para presentar mejor tu empresa y generar nuevas oportunidades.','footer.contact':'CONTACTO','footer.location':'UBICACIÓN'}
};
function safeStoreGet(key){try{return localStorage.getItem(key)}catch(_){return null}}
function safeStoreSet(key,value){try{localStorage.setItem(key,value)}catch(_){}}
function setLang(lang){document.documentElement.lang=lang==='pt'?'pt-BR':lang;document.querySelectorAll('[data-i18n]').forEach(el=>{const k=el.dataset.i18n;let v=lang==='pt'?null:T[lang]?.[k];if(v!=null)el.innerHTML=v;else if(lang==='pt'&&el.dataset.pt)el.innerHTML=el.dataset.pt});document.querySelectorAll('.langs button').forEach(b=>b.classList.toggle('active',b.dataset.lang===lang));safeStoreSet('linkefy-lang',lang)}
// preserve Portuguese source strings for switching back
const ptText={};document.querySelectorAll('[data-i18n]').forEach(el=>{ptText[el.dataset.i18n]=el.innerHTML;el.dataset.pt=el.innerHTML});document.querySelectorAll('.langs button').forEach(b=>b.addEventListener('click',()=>setLang(b.dataset.lang)));setLang(safeStoreGet('linkefy-lang')||'pt');

// =========================================================
// Interaction pass : reference-inspired hover / pointer motion
// =========================================================
(function(){
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  const fine = matchMedia('(hover:hover) and (pointer:fine)').matches;
  if(reduce || !fine) return;

  // cursor easing + press state
  const c=document.getElementById('cursor');
  if(c){
    let mx=-100,my=-100,cx=-100,cy=-100,raf=0;
    addEventListener('mousemove',e=>{mx=e.clientX;my=e.clientY;if(!raf) raf=requestAnimationFrame(tick)},{passive:true});
    addEventListener('mousedown',()=>c.classList.add('is-down'));
    addEventListener('mouseup',()=>c.classList.remove('is-down'));
    addEventListener('mouseleave',()=>{c.style.opacity='0'});
    addEventListener('mouseenter',()=>{c.style.opacity='1'});
    function tick(){cx+=(mx-cx)*.2;cy+=(my-cy)*.2;c.style.left=cx+'px';c.style.top=cy+'px';raf=requestAnimationFrame(tick)}
  }

  // magnetic CTAs
  document.querySelectorAll('.btn').forEach(btn=>{
    btn.addEventListener('mousemove',e=>{
      const r=btn.getBoundingClientRect();
      const x=(e.clientX-r.left-r.width/2)/r.width;
      const y=(e.clientY-r.top-r.height/2)/r.height;
      btn.style.setProperty('--mx',(x*8).toFixed(2)+'px');
      btn.style.setProperty('--my',(y*5).toFixed(2)+'px');
    });
    btn.addEventListener('mouseleave',()=>{btn.style.setProperty('--mx','0px');btn.style.setProperty('--my','0px')});
  });

  // cursor-position glow on premium cards
  const spotCards=document.querySelectorAll('.feature-card,.service-card,.cred-card,.always-card,.signature-card');
  spotCards.forEach(card=>{
    card.addEventListener('mousemove',e=>{
      const r=card.getBoundingClientRect();
      card.style.setProperty('--spot-x',`${e.clientX-r.left}px`);
      card.style.setProperty('--spot-y',`${e.clientY-r.top}px`);
    });
  });

  // subtle 3D tilt (small enough to preserve editorial feel)
  document.querySelectorAll('.feature-card,.service-card').forEach(card=>{
    card.addEventListener('mousemove',e=>{
      const r=card.getBoundingClientRect(), px=(e.clientX-r.left)/r.width-.5, py=(e.clientY-r.top)/r.height-.5;
      const lift=card.classList.contains('service-card')?-5:-6;
      card.style.transform=`perspective(900px) translateY(${lift}px) rotateX(${(-py*2.1).toFixed(2)}deg) rotateY(${(px*2.1).toFixed(2)}deg)`;
    });
    card.addEventListener('mouseleave',()=>card.style.transform='');
  });

  // hero background moves a few pixels with pointer + scroll
  const hero=document.getElementById('inicio'), heroBg=hero?.querySelector('.hero-bg');
  let hx=0,hy=0,scrollShift=0;
  function renderHero(){if(heroBg) heroBg.style.transform=`translate3d(${hx}px,${hy+scrollShift}px,0) scale(1.025)`}
  hero?.addEventListener('mousemove',e=>{
    const r=hero.getBoundingClientRect();
    hx=((e.clientX-r.left)/r.width-.5)*-10;
    hy=((e.clientY-r.top)/r.height-.5)*-7;
    renderHero();
  });
  hero?.addEventListener('mouseleave',()=>{hx=0;hy=0;renderHero()});
  addEventListener('scroll',()=>{scrollShift=Math.max(-18,Math.min(0,-scrollY*.018));renderHero()},{passive:true});

  // interactive device scene parallax
  const always=document.querySelector('.always-card'), laptop=always?.querySelector('.laptop'), phone=always?.querySelector('.phone');
  if(always && laptop && phone){
    always.addEventListener('mousemove',e=>{
      const r=always.getBoundingClientRect(),x=(e.clientX-r.left)/r.width-.5,y=(e.clientY-r.top)/r.height-.5;
      laptop.style.transform=`translate3d(${(x*-10).toFixed(1)}px,${(y*-5).toFixed(1)}px,0) rotate(-6deg) rotateY(${(x*2).toFixed(1)}deg)`;
      phone.style.transform=`translate3d(${(x*12).toFixed(1)}px,${(y*7).toFixed(1)}px,0) rotate(5deg) rotateY(${(x*-3).toFixed(1)}deg)`;
    });
    always.addEventListener('mouseleave',()=>{laptop.style.transform='';phone.style.transform=''})
  }

  // Linkefy signature symbol follows pointer subtly
  const sig=document.querySelector('.signature-card'), sigSymbol=sig?.querySelector('.big-symbol');
  if(sig && sigSymbol){
    sig.addEventListener('mousemove',e=>{
      const r=sig.getBoundingClientRect(),x=(e.clientX-r.left)/r.width-.5,y=(e.clientY-r.top)/r.height-.5;
      sigSymbol.style.transform=`translate3d(${(x*18).toFixed(1)}px,${(y*14).toFixed(1)}px,0) rotate(${(x*3).toFixed(1)}deg)`;
    });
    sig.addEventListener('mouseleave',()=>sigSymbol.style.transform='');
  }

  // Accordion's active item gets a controlled transition and visual synchrony
  document.querySelectorAll('.acc-item').forEach(item=>{
    item.addEventListener('mouseenter',()=>item.classList.add('is-hovered'));
    item.addEventListener('mouseleave',()=>item.classList.remove('is-hovered'));
  });

  // Pause moving rows only while the user is actually inspecting them
  document.querySelectorAll('.project-placeholder').forEach(card=>{
    card.addEventListener('mouseenter',()=>card.closest('.project-track')?.style.setProperty('animation-play-state','paused'));
    card.addEventListener('mouseleave',()=>card.closest('.project-track')?.style.removeProperty('animation-play-state'));
  });
})();


// Scroll-build experience V8 : every section builds on entry and rearms after exit
(function(){
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  if(reduce) return;

  const configs = [
    {sel:'#inicio', title:'.display', groups:[['header','soft',0,0],['.hero-copy','soft',70,0],['.hero-proof','scale',220,0]]},
    {sel:'.benefit-loop', groups:[['.benefit-track','soft',0,0],['.pill','scale',80,28]]},
    {sel:'#sec02', title:'.showcase-head h2', groups:[['.showcase-head','soft',0,0],['.project-row.a','left',120,0],['.project-row.b','right',250,0]]},
    {sel:'#sec04', title:'.cred-title', groups:[['.cred-box','clip',0,0],['.cred-card','scale',150,140]]},
    {sel:'#servicos', title:'.practice-title', groups:[['.practice-title','soft',0,0],['.practice-visual','clip',120,0],['.acc-item','right',170,72]]},
    {sel:'#servicos-completos', title:'.full-services-head h2', groups:[['.full-services-head','soft',0,0],['.service-card','scale',130,92]]},
    {sel:'#sec06', title:'.always-card h2', groups:[['.always-card','clip',0,0],['.always-card h2','soft',130,0],['.device-scene','scale',270,0],['.sale-note','soft',420,90]]},
    {sel:'#projetos', title:'.portfolio-head .h1', groups:[['.portfolio-head','soft',0,0],['.project-card','scale',140,130]]},
    {sel:'#sec08', groups:[['.ba-copy','left',0,0],['.notebook','scale',140,0],['.notebook-screen','clip',220,0]]},
    {sel:'#sec09', title:'.competitor-inner h2', groups:[['.competitor-inner','soft',40,0],['.competitor-inner .btn','scale',220,0]]},
    {sel:'#contato', title:'.signature-card h2', groups:[['.signature-card','scale',0,0],['.signature-card .btn','soft',220,0],['.big-symbol','soft',300,0]]},
    {sel:'.footer', groups:[['.footer-brand','soft',0,0],['.footer-col','soft',110,110],['.footer-bottom','soft',330,0]]}
  ];

  const states=[];
  const allSections=new Set();

  function nodesFor(section, selector){
    if(section.matches(selector)) return [section];
    return Array.from(section.querySelectorAll(selector));
  }

  function prepare(cfg){
    const section=document.querySelector(cfg.sel);
    if(!section) return;
    allSections.add(section);
    section.classList.add('build-divider');
    const title=cfg.title?section.querySelector(cfg.title):null;
    if(title) title.classList.add('scroll-build-title');
    const targets=[];
    cfg.groups.forEach(([selector,type,baseDelay,step])=>{
      nodesFor(section,selector).forEach((el,index)=>{
        el.classList.add('scroll-build-item');
        if(type) el.classList.add('build-'+type);
        el.style.setProperty('--build-delay',(baseDelay+(step||0)*index)+'ms');
        targets.push(el);
      });
    });
    const state={section,title,targets,played:false};
    state.reset=()=>{
      state.played=false;
      section.classList.remove('build-divider-in');
      title?.classList.remove('title-built');
      targets.forEach(el=>el.classList.remove('built'));
    };
    state.play=()=>{
      if(state.played) return;
      state.played=true;
      section.classList.add('build-divider-in');
      requestAnimationFrame(()=>{
        title?.classList.add('title-built');
        targets.forEach(el=>el.classList.add('built'));
      });
    };
    state.reset();
    states.push(state);
  }
  configs.forEach(prepare);

  // Fallback: any direct page section not explicitly configured still receives a build effect.
  document.querySelectorAll('main > section').forEach(section=>{
    if(allSections.has(section)) return;
    const targets=Array.from(section.querySelectorAll('.reveal, h2, h3')).slice(0,12);
    targets.forEach((el,i)=>{
      el.classList.add('scroll-build-item','build-soft');
      el.style.setProperty('--build-delay',(i*70)+'ms');
    });
    const state={section,title:null,targets,played:false};
    state.reset=()=>{state.played=false;targets.forEach(el=>el.classList.remove('built'))};
    state.play=()=>{if(state.played)return;state.played=true;requestAnimationFrame(()=>targets.forEach(el=>el.classList.add('built')))};
    state.reset();
    states.push(state);
  });

  let raf=0,lastY=scrollY;
  function update(){
    raf=0;
    const vh=innerHeight||document.documentElement.clientHeight;
    const y=scrollY;
    const direction=y>=lastY?1:-1;
    lastY=y;
    states.forEach(state=>{
      const r=state.section.getBoundingClientRect();
      const fullyOut = r.bottom < -80 || r.top > vh + 80;
      if(fullyOut){
        if(state.played) state.reset();
        return;
      }
      // Trigger as the section enters from either scroll direction.
      const entersFromBottom = r.top < vh*.88 && r.bottom > vh*.18;
      const entersFromTop = r.bottom > vh*.12 && r.top < vh*.78;
      if(!state.played && (direction>=0 ? entersFromBottom : entersFromTop)) state.play();
    });
  }
  function schedule(){if(!raf) raf=requestAnimationFrame(update)}
  addEventListener('scroll',schedule,{passive:true});
  addEventListener('resize',schedule,{passive:true});
  addEventListener('pageshow',()=>{states.forEach(s=>s.reset());requestAnimationFrame(update)});
  document.addEventListener('visibilitychange',()=>{if(!document.hidden) requestAnimationFrame(update)});
  document.querySelectorAll('a[href^="#"]').forEach(a=>a.addEventListener('click',()=>setTimeout(schedule,80)));
  requestAnimationFrame(update);
})();

