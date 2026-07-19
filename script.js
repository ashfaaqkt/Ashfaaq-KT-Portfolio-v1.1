/* ============================================
   FUTURISTIC PORTFOLIO - MAIN SCRIPT (Protected)
   ============================================ */

// ============================================
// PDF SHIELD (CRITICAL - ATTACHED IMMEDIATELY)
// ============================================

// Fetches a protected PDF via Authorization header and opens it as a blob URL.
// Defined on window so the IIFE shield and post-login handlers can both call it.
window.openProtectedPDF = async function(pdfUrl, token) {
  try {
    const response = await fetch(pdfUrl, {
      headers: { 'Authorization': 'Bearer ' + token }
    });
    if (response.status === 401) {
      // Token expired — clear auth state and prompt re-login
      localStorage.removeItem('portfolio_token');
      localStorage.removeItem('portfolio_user');
      window.pendingPdfLink = pdfUrl;
      if (typeof window.openAuthModal === 'function') window.openAuthModal('login');
      return;
    }
    if (!response.ok) {
      console.error('PDF Shield: server rejected request', response.status);
      return;
    }
    const blob = await response.blob();
    const blobUrl = URL.createObjectURL(blob);
    window.open(blobUrl, '_blank');
  } catch (err) {
    console.error('PDF Shield: failed to load PDF', err);
  }
};

(function() {
  const handleGlobalClick = (e) => {
    const link = e.target.closest('a');
    if (!link || !link.href) return;

    const url = link.href.toLowerCase();
    const isPDF = url.includes('.pdf');

    if (isPDF) {
      // LOCKED if it's NOT in /OCC/ or explicitly whitelisted
      // EXCEPT for specific certificates which should ALWAYS be locked
      const decodedUrl = decodeURIComponent(url);
      // Entri & NSDC subfolder is protected regardless of /occ/ prefix
      const isProtectedOCCPath = decodedUrl.includes('/occ/entri');
      const isCertificate = (url.includes('/occ/') || link.classList.contains('certificate-link')) &&
                            !isProtectedOCCPath &&
                            !url.includes('hscertificate') &&
                            !url.includes('high%20school') &&
                            !url.includes('aiu%20certificate');

      if (!isCertificate) {
        // Always intercept — authenticated users also go through the secure fetch path
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();

        const token = localStorage.getItem('portfolio_token');
        const isValid = token && token !== 'null' && token !== 'undefined' && token.length > 20;

        if (!isValid) {
          console.warn('PDF Shield: Blocked unauthenticated access to', url);
          window.pendingPdfLink = link.href;
          if (typeof window.openAuthModal === 'function') {
            window.openAuthModal('signup');
          } else {
            // Fallback if global function isn't ready
            const modal = document.getElementById('auth-modal');
            if (modal) {
              modal.setAttribute('aria-hidden', 'false');
              document.body.classList.add('no-scroll');
              document.documentElement.classList.add('no-scroll');
            }
          }
        } else {
          // Authenticated — open via secure backend route (sends JWT, gets blob)
          window.openProtectedPDF(link.href, token);
        }
      }
    }
  };

  // Attach to window using capture to ensure we are first
  window.addEventListener('click', handleGlobalClick, { capture: true });
})();

// ============================================
// LANGUAGE & TRANSLATIONS & THEME
// ============================================

let currentLanguage = localStorage.getItem('portfolio-language') || 'en';
document.documentElement.setAttribute('data-theme', localStorage.getItem('portfolio-theme') || 'dark');

// API configuration
const API_BASE_URL = '/api';

const translations = {
  en: {
    // Navigation
    nav: {
      home: 'Home',
      about: 'About',
      education: 'Education',
      projects: 'Projects',
      fyp: 'FYP',
      expertise: 'Expertise',
      connect: 'Connect'
    },
    // Hero Section
    hero: {
      greeting: 'Hello I Am',
      name: 'Ashfaaq KT',
      degree: 'BSc. CS - BITS PILANI',
      description: 'Results driven full-stack developer blending expertise in the MERN stack, seamless cloud integration, and UI/UX design with a strong focus on AI-assisted workflows. Backed by formal training in Computer Science and hands-on experience building scalable, intelligent platforms, I specialize in streamlining DevOps and data analysis to engineer fast, high-performance digital experiences.',
      cgpa: 'CGPA',
      graduation: 'Graduation',
      languages: 'Languages',
      projects: 'Projects',
      quote: 'So Give Me Coffee And Codes...'
    },
    // About Section
    about: {
      label: 'Profile',
      title: 'Engineering thoughtful software experiences',
      subtitle: 'Blending clean architecture, secure backend logic, and AI-enhanced workflows to deliver solutions that scale with confidence.',
      techStack: 'Technology Stack',
      card1: {
        title: 'Software Engineering & AI',
        subtitle: 'BITS PILANI',
        description: 'Experienced across diverse product domains, from cloud infrastructure to enterprise software solutions. Comfortable collaborating with international clients and working seamlessly within multilingual development teams. I focus on writing clean, maintainable code that stands the test of time.'
      },
      card2: {
        title: 'MERN Full-Stack Development',
        subtitle: 'Entri Elevate, Kochi · A+ Grade · NSDC Certified',
        description: 'Building end-to-end applications with modern frameworks. From responsive UIs that delight users to robust APIs that handle scale. Every layer is crafted with attention to performance, security, and user experience.'
      },
      card3: {
        title: 'AI-Assisted Workflows',
        subtitle: 'Prompt Engineering',
        description: 'Leveraging cutting-edge AI tools to accelerate development without compromising quality. Mastering prompt engineering and AI-assisted coding to build faster, smarter, and more efficiently. The future of development is collaborative.'
      }
    },
    // Education Section
    education: {
      label: 'Timeline',
      title: 'Academic journey & milestones',
      timeline: [
        {
          badge: '2024 — Present',
          title: 'AshTech Solutions · Founder & Full-Stack Developer',
          subtitle: 'Software Solutions Agency',
          description: 'Architected and deployed a production-ready agency website with an integrated AI chatbot, serverless backend, and custom domain routing. Building software solutions for clients globally.',
          links: [
            { text: 'Visit AshTech', href: 'https://www.ashtechnologiesolutions.com/' }
          ]
        },
        {
          badge: '2023 — Present',
          title: 'BITS Pilani · B.Sc. Computer Science',
          subtitle: 'Online Program · CGPA 7.91',
          description: 'Final-year coursework focused on systems architecture, artificial intelligence, database management, and full-stack engineering. Actively building portfolio projects aligned with industry readiness and modern software development practices.',
          links: [
            { text: 'Performance Sheet', href: 'BITS/prfmnc.pdf' },
            { text: 'SEM 1 Grades', href: 'BITS/SEM1.pdf' },
            { text: 'SEM 2 Grades', href: 'BITS/SEM2.pdf' },
            { text: 'SEM 3 Grades', href: 'BITS/SEM3.pdf' },
            { text: 'SEM 4 Grades', href: 'BITS/SEM4.pdf' },
            { text: 'SEM 5 Grades', href: 'BITS/SEM5.pdf' }
          ]
        },
        {
          badge: '2025 — 2026',
          title: 'Entri Elevate · AI-Based Full Stack Development',
          subtitle: 'Kochi, Kerala · MERN Stack · A+ Grade',
          description: 'Completed an intensive AI-powered full-stack development program at Entri Elevate, Kochi. Mastered the complete MERN stack — MongoDB, Express.js, React, and Node.js — through rigorous hands-on projects covering RESTful API design, JWT authentication, cloud deployment, and AI-integrated workflows. Graduated with an A+ Grade and earned dual certification from Entri and NSDC (National Skill Development Corporation), validating industry-ready competency in modern web development.',
          links: [
            { text: 'Entri Certificate', href: 'OCC/Entri & NSDC/Ashfaaq Entri cer.pdf' },
            { text: 'NSDC Certificate', href: "OCC/Entri & NSDC/Ashfaaq's NSDC.pdf" }
          ]
        },
        {
          badge: '2019 — 2021',
          title: 'Al-Shatti Secondary School',
          subtitle: 'Dammam, Saudi Arabia · GPA 98%',
          description: 'Science track focused on logical reasoning, advanced mathematics, and bilingual presentation skills. Educated under the Saudi Ministry of Education (Arabic medium), gaining strong proficiency in both Arabic and English, especially through dual-language instruction in science and mathematics.',
          links: [
            { text: 'AIU Equivalency Certificate', href: 'HSCertificate/AIU%20CERTIFICATE.pdf' },
            { text: 'High School Certificate', href: 'HSCertificate/High%20school%20certificate%20.pdf' }
          ]
        },
        {
          badge: 'Certifications',
          title: 'Professional Certificates',
          subtitle: 'Technical Skill Development',
          description: 'Earned various certifications from reputable institutions to strengthen foundations in programming and design.',
          links: [
            { text: 'Figma Basics', href: 'OCC/Figma certificate.pdf' },
            { text: 'Introduction to Programming (BITS)', href: 'OCC/ITP by bits.pdf' },
            { text: 'Basics of Python (University of Michigan)', href: 'OCC/python by coursera.pdf' },
            { text: 'AWS Assessment (LearnTube)', href: 'OCC/LT AWS Assessment.png' }
          ]
        },
        {
          badge: '2026',
          title: '2026 — Graduation Target & Research Pathway',
          subtitle: 'August 29, 2026',
          description: 'Finalizing a production-grade multimodal document intelligence pipeline for my BITS Pilani graduation capstone by August 29. Actively scaling zero-shot VLM architecture and schema enforcement protocols to bridge the gap in low-resource Arabic-script document benchmarks. Building a foundational research portfolio to transition directly into VSRP internships and integrated MS/PhD pathways.',
          milestones: [
            'Multimodal Pipelines Deployed',
            'VLM Instruction Frameworks Mastered',
            'Ready for Advanced AI Research & PG Roles'
          ]
        },
        {
          badge: '2022 — Present',
          title: 'Growly Farms · Co-Founder & Director',
          subtitle: 'Wandoor, Kerala, India · Organic Agriculture',
          description: 'Co-founded with Nabhan KT, Growly Farms is a 5-acre organic farm in Wandoor, Kerala, cultivating Rambutan, Jackfruit, Dragonfruit, Papaya, and more. Powered by modern drip irrigation and precision nutrient delivery systems from NETFM, the farm blends traditional organic principles with modern agricultural technology. Our vision is HighTech Farm Tourism, hydroponic expansion, and AI/ML-driven crop intelligence — making farming smarter, greener, and more productive.',
          milestones: [
            'Organic 5-Acre Multi-Crop Farm Established',
            'NETFM Drip Irrigation & Supplement Systems Deployed',
            'Vision: HiTech Farm Tourism · Hydroponics · AI & ML Integration'
          ],
          links: [
            { text: 'Follow on Instagram @growly.kl', href: 'https://www.instagram.com/growly.kl' }
          ]
        }
      ]
    },
    // Projects Section
    projects: {
      label: 'Portfolio',
      title: 'Selected projects & experiments',
      subtitle: 'From production-ready systems to experimental builds, each project represents a step forward in technical excellence.',
      exploreAll: 'Explore All Projects'
    },
    // Expertise Section
    expertise: {
      label: 'Capabilities',
      title: 'Skills, languages & hobbies',
      languagesTitle: 'Languages & Communication',
      hobbiesTitle: 'Hobbies',
      filters: {
        all: 'All',
        frontend: 'Front End',
        uiux: 'UI/UX Design',
        backend: 'Back End',
        mobile: 'Android / iOS',
        ai: 'AI & Cloud',
        tools: 'Tools',
        soft: 'Soft Skills',
        others: 'Others'
      }
    },
    // Connect Section
    connect: {
      label: 'Contact',
      title: "Let's build something together",
      subtitle: 'Open to remote and hybrid opportunities. Comfortable working across time zones in India and Saudi Arabia.',
      getInTouch: 'Get in Touch',
      email: 'Email',
      workEmail: 'Work Email',
      personalEmail: 'Personal Email',
      phoneIN: 'Phone (IN)',
      sendMessage: 'Send a Message',
      name: 'Name',
      namePlaceholder: 'Your name',
      emailPlaceholder: 'your.email@example.com',
      message: 'Message',
      messagePlaceholder: 'Your message here...',
      category: 'Category',
      individual: 'Individual',
      company: 'Company',
      other: 'Other',
      otherLabel: 'Please specify',
      otherPlaceholder: 'Specify your category',
      send: 'Send Message'
    },
    // Footer
    footer: {
      navigation: 'Navigation',
      connect: 'Connect',
      social: 'Social Media',
      status: 'Status',
      statusText: 'AI-Assisted SWE | Open to Remote, Hybrid & Onsite roles in India & GCC.',
      navLinks: {
        home: 'Home',
        about: 'About',
        education: 'Education',
        projects: 'Projects',
        expertise: 'Expertise',
        connect: 'Connect'
      }
    },
    // Chatbot
    chatbot: {
      welcomeMessage: 'Hi! 👋 I\'m Ashfaaq\'s portfolio assistant. Tap a question below to learn more about me!',
      faqButtons: {
        about: 'About Ashfaaq',
        finalProject: 'Final Year Project',
        education: 'Education',
        projects: 'Projects',
        skills: 'Skills',
        contact: 'Contact'
      },
      answers: {
        about: `<p><strong>Ashfaaq KT</strong> is a results-driven <strong>AI-Assisted Full-Stack Developer</strong> and final-year B.Sc. Computer Science student at <strong>BITS Pilani</strong> (CGPA 7.91), graduating August 2026.</p>
          <p>He blends expertise in the <strong>MERN stack</strong>, seamless cloud integration, UI/UX design, and AI-assisted workflows to build fast, scalable, intelligent digital platforms.</p>
          <ul>
            <li>🏢 <strong>Founder & CTO</strong> — AshTech Software Solutions (2024–Present)</li>
            <li>🌱 <strong>Co-Founder & Director</strong> — Growly Farms, Kerala (2022–Present)</li>
            <li>🎓 <strong>MERN Full-Stack</strong> — Entri Elevate AI Program (2025–Present)</li>
            <li>🌍 Comfortable working in <strong>India & GCC</strong> time zones</li>
            <li>🗣️ Fluent in <strong>Arabic, English & Malayalam</strong></li>
          </ul>
          <p>Open to <strong>remote, hybrid & onsite</strong> roles in India and GCC. <a href="#about" onclick="navigateToPage('about'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">Read more →</a></p>`,

        education: `<p>📚 <strong>Academic & Professional Timeline:</strong></p>
          <ul>
            <li>🎓 <strong>B.Sc. Computer Science — BITS Pilani</strong> (2023–2026)<br>Online Program · CGPA <strong>7.91</strong> · Final Year · Graduating Aug 29, 2026</li>
            <li>💻 <strong>AI-Based Full-Stack Dev — Entri Elevate</strong> (2025–2026)<br>MERN Stack · A+ Grade · Dual certified by Entri & NSDC · Kochi</li>
            <li>🏫 <strong>Al-Shatti Secondary School</strong> — Dammam, Saudi Arabia (2019–2021)<br>Science Track · GPA <strong>98%</strong> · Saudi Ministry of Education</li>
          </ul>
          <p>📜 <strong>Certifications:</strong> Figma Basics · Introduction to Programming (BITS) · Python (University of Michigan / Coursera) · AWS Assessment (LearnTube)</p>
          <p><a href="#education" onclick="navigateToPage('education'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">View full timeline & certificates →</a></p>`,

        projects: `<p>🚀 Ashfaaq has <strong>20+ projects</strong> spanning full-stack, AI, data, systems & design:</p>
          <ul>
            <li>🛍️ <strong>Basket Store</strong> — MERN E-Commerce + Gemini AI chat & product insights</li>
            <li>📖 <strong>StudyBuddy</strong> — Full-stack EdTech app · JWT auth · AI note summarizer · Pomodoro · Analytics dashboard</li>
            <li>🌐 <strong>AshTech Solutions</strong> — Live agency website · AI chatbot · Serverless backend</li>
            <li>🏦 <strong>Banking gRPC System</strong> — Python · SQL · gRPC · Auth layers · Transaction engine</li>
            <li>☁️ <strong>AWS RDS Integration</strong> — Production DB schemas · Automated backups · High availability</li>
            <li>📊 <strong>Tableau Dashboards</strong> — Mental Health analysis · Airbnb pricing & occupancy insights</li>
            <li>⚙️ <strong>DevOps Workflow</strong> — Git · Docker · Flask · CI/CD pipeline</li>
            <li>🖥️ <strong>HTTP Client in C</strong> — Raw TCP sockets · Network protocol programming</li>
            <li>📱 <strong>ETTI App UI/UX</strong> — Multi-service delivery app mockup · iPad / MockUp</li>
            <li>🐍 <strong>Football Player Analysis</strong> — Python · Pandas · EDA · Market valuation</li>
          </ul>
          <p><a href="#projects" onclick="navigateToPage('projects'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">Browse all projects →</a> · <a href="https://github.com/ashfaaqkt" target="_blank">GitHub ↗</a></p>`,

        skills: `<p>💡 <strong>Full skill breakdown from Ashfaaq's ATS CV:</strong></p>
          <ul>
            <li>⚛️ <strong>Frontend:</strong> React · HTML5 · CSS3 · JavaScript · Responsive Design · Web Animations · UI/UX Design</li>
            <li>🎨 <strong>UI/UX:</strong> Figma · Adobe XD · MockUp (iPad) · Canva Pro · DaVinci Resolve · PicsArt</li>
            <li>🔧 <strong>Backend:</strong> Node.js · Express.js · Python · Flask · gRPC · C Programming</li>
            <li>🗄️ <strong>Databases:</strong> MongoDB · MySQL · AWS RDS · Firebase</li>
            <li>📱 <strong>Mobile:</strong> Kotlin · Swift · Android Studio</li>
            <li>🤖 <strong>AI & Cloud:</strong> LLM Prompt Engineering · Gemini API · AI-Assisted Development · Cloud Services · Data Analysis & Visualization</li>
            <li>🛠️ <strong>Tools:</strong> Git · GitHub · Docker · Tableau · Cursor IDE · VS Code · Replit · Framer · Notion · Linux</li>
            <li>🌿 <strong>Other:</strong> Interior Design · SketchUp / 5D Planner · AutoCAD · Modern Farming · AgriTech</li>
          </ul>
          <p><a href="#expertise" onclick="navigateToPage('expertise'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">Explore full expertise →</a></p>`,

        contact: `<p>📬 <strong>Get in touch with Ashfaaq:</strong></p>
          <ul>
            <li>💼 <strong>Work Email:</strong> <a href="mailto:hire.me@ashfaaqkt.com">hire.me@ashfaaqkt.com</a></li>
            <li>📧 <strong>Personal Email:</strong> <a href="mailto:ashfaaqktmail@gmail.com">ashfaaqktmail@gmail.com</a></li>
            <li>📞 <strong>Phone (India):</strong> <a href="tel:+919995032407">+91 99950 32407</a></li>
            <li>💬 <strong>WhatsApp:</strong> <a href="https://wa.me/919995032407?text=Hello%20Ashfaaq" target="_blank">Chat on WhatsApp ↗</a></li>
            <li>🏢 <strong>AshTech:</strong> <a href="https://www.ashtechnologiesolutions.com/" target="_blank">ashtechnologiesolutions.com ↗</a></li>
            <li>💻 <strong>GitHub:</strong> <a href="https://github.com/ashfaaqkt" target="_blank">github.com/ashfaaqkt ↗</a></li>
          </ul>
          <p>Open to <strong>Remote · Hybrid · Onsite</strong> roles in India & GCC. <a href="#connect" onclick="navigateToPage('connect'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">Send a message →</a></p>`,

        finalProject: `<p>🎓 <strong>BITS Pilani Final Year Project (Capstone)</strong></p>
          <p><strong>Bill Scanning Based Reward & Intelligence System</strong></p>
          <ul>
            <li>🧠 <strong>Stack:</strong> MERN · Firebase · Python · Gemini API · AI/ML · React</li>
            <li>📄 <strong>What it does:</strong> Scans physical bills using AI vision, extracts structured data (items, totals, vendor) via Google Gemini API, and powers a dynamic reward & loyalty engine for end users.</li>
            <li>⚙️ <strong>Architecture:</strong> Multimodal AI pipeline · Zero-shot document extraction · Serverless Firebase backend · Scalable reward logic</li>
            <li>🏆 <strong>Phase:</strong> PoC Phase 3 — Team ARAJ · Production-grade build</li>
            <li>📅 <strong>Graduation target:</strong> August 29, 2026 — Aiming for VSRP internships & MS/PhD research pathways in AI</li>
          </ul>
          <p><a href="https://github.com/ashfaaqkt/Bill-Scanning-Based-Reward-Intelligence-System-study-project-bits-poc-phase-3-Team-ARAJ" target="_blank">GitHub Repo ↗</a> &nbsp;·&nbsp; <a href="https://ashfaaqkt.github.io/Bill-Scanning-Based-Reward-Intelligence-System-study-project-bits-poc-phase-3-Team-ARAJ/public/index.html" target="_blank">Live Demo ↗</a></p>`
      }
    }
  },
  ar: {
    // Navigation
    nav: {
      home: 'الرئيسية',
      about: 'نبذة',
      education: 'التعليم',
      projects: 'المشاريع',
      fyp: 'التخرج',
      expertise: 'الخبرات',
      connect: 'التواصل'
    },
    // Hero Section
    hero: {
      greeting: 'مرحباً أنا',
      name: 'اشفاق كي تي',
      degree: 'بكالوريوس علوم الحاسوب - معهد بتس بيلاني التقنية',
      description: 'مطور Full-Stack موجه نحو النتائج، يمزج بين الخبرة في MERN stack، والتكامل السلس مع السحابة، وتصميم UI/UX، مع تركيز قوي على سير العمل المدعومة بالذكاء الاصطناعي. مدعومًا بتدريب أكاديمي رسمي في علوم الحاسوب وخبرة عملية في بناء منصات ذكية وقابلة للتوسع، أتخصص في تبسيط DevOps وتحليل البيانات لهندسة تجارب رقمية سريعة وعالية الأداء.',
      cgpa: 'المعدل',
      graduation: 'التخرج',
      languages: 'اللغات',
      projects: 'المشاريع',
      quote: 'فقط أعطني القهوة والأكواد...'
    },
    // About Section
    about: {
      label: 'الملف الشخصي',
      title: 'هندسة تجارب برمجية مدروسة',
      subtitle: 'دمج البنية النظيفة، منطق الخلفية الآمن، وسير العمل المعززة بالذكاء الاصطناعي لتقديم حلول تتوسع بثقة.',
      techStack: 'المجموعة التقنية',
      card1: {
        title: 'هندسة البرمجيات والذكاء الاصطناعي',
        subtitle: 'معهد بتس بيلاني التقنية',
        description: 'خبرة عبر مجالات منتجات متنوعة، من البنية التحتية السحابية إلى حلول البرمجيات المؤسسية. مرتاح في التعاون مع العملاء الدوليين والعمل بسلاسة ضمن فرق التطوير متعددة اللغات. أركز على كتابة كود نظيف وقابل للصيانة يثبت أمام اختبار الزمن.'
      },
      card2: {
        title: 'تطوير MERN الكامل',
        subtitle: 'إنتراي إلفيت، كوتشي · تقدير A+ · معتمد من NSDC',
        description: 'بناء تطبيقات شاملة بإطارات حديثة. من واجهات المستخدم المتجاوبة التي تسعد المستخدمين إلى واجهات برمجة التطبيقات القوية التي تتعامل مع الحجم. كل طبقة مصممة بعناية للأداء والأمان وتجربة المستخدم.'
      },
      card3: {
        title: 'سير العمل المدعومة بالذكاء الاصطناعي',
        subtitle: 'هندسة المطالبات',
        description: 'الاستفادة من أدوات الذكاء الاصطناعي المتطورة لتسريع التطوير دون المساس بالجودة. إتقان هندسة المطالبات والبرمجة المدعومة بالذكاء الاصطناعي للبناء بشكل أسرع وأذكى وأكثر كفاءة. مستقبل التطوير تعاوني.'
      }
    },
    // Education Section
    education: {
      label: 'الجدول الزمني',
      title: 'الرحلة الأكاديمية والمعالم',
      timeline: [
        {
          badge: '2024 — الحاضر',
          title: 'حلول آش تك · مؤسس ومطور Full-Stack',
          subtitle: 'وكالة حلول برمجية',
          description: 'تصميم ونشر موقع وكالة جاهز للإنتاج مع برنامج دردشة آلي مدمج، وخلفية بدون خادم، وتوجيه نطاق مخصص. بناء حلول برمجية للعملاء عالمياً.',
          links: [
            { text: 'زيارة آش تك', href: 'https://www.ashtechnologiesolutions.com/' }
          ]
        },
        {
          badge: '2023 — الحاضر',
          title: 'معهد بتس بيلاني التقنية · بكالوريوس علوم الحاسوب',
          subtitle: 'اونلاين · المعدل التراكمي 7.91',
          description: 'دورات السنة الأخيرة تركز على هندسة الأنظمة، الذكاء الاصطناعي، إدارة قواعد البيانات، وهندسة المكدس الكامل. بناء مشاريع محفظة نشطة تتماشى مع جاهزية الصناعة وممارسات تطوير البرمجيات الحديثة.',
          links: [
            { text: 'ورقة الأداء', href: 'BITS/prfmnc.pdf' },
            { text: 'درجات الفصل الأول', href: 'BITS/SEM1.pdf' },
            { text: 'درجات الفصل الثاني', href: 'BITS/SEM2.pdf' },
            { text: 'درجات الفصل الثالث', href: 'BITS/SEM3.pdf' },
            { text: 'درجات الفصل الرابع', href: 'BITS/SEM4.pdf' },
            { text: 'درجات الفصل الخامس', href: 'BITS/SEM5.pdf' }
          ]
        },
        {
          badge: '2025 — 2026',
          title: 'إنتراي إلفيت · تطوير الويب الكامل القائم على الذكاء الاصطناعي',
          subtitle: 'كوتشي، كيرالا · مكدس MERN · تقدير A+',
          description: 'أتممت برنامجاً مكثفاً لتطوير الويب الكامل المدعوم بالذكاء الاصطناعي في إنتراي إلفيت، كوتشي. أتقنت مكدس MERN الكامل — MongoDB و Express.js و React و Node.js — من خلال مشاريع عملية متقدمة تغطي تصميم RESTful API ومصادقة JWT والنشر السحابي وسير العمل المدمجة بالذكاء الاصطناعي. تخرجت بتقدير A+ وحصلت على شهادة مزدوجة من إنتراي و NSDC (المجلس القومي لتنمية المهارات).',
          links: [
            { text: 'شهادة إنتراي', href: 'OCC/Entri & NSDC/Ashfaaq Entri cer.pdf' },
            { text: 'شهادة NSDC', href: "OCC/Entri & NSDC/Ashfaaq's NSDC.pdf" }
          ]
        },
        {
          badge: '2019 — 2021',
          title: 'مدرسة الشاطئ الثانوية',
          subtitle: 'الدمام، المملكة العربية السعودية · المعدل 98%',
          description: 'مسار علمي يركز على التفكير المنطقي، الرياضيات المتقدمة، ومهارات العرض ثنائية اللغة. تعليم تحت إشراف وزارة التعليم السعودية (اللغة العربية)، اكتساب إتقان قوي في كل من العربية والإنجليزية، خاصة من خلال التعليم ثنائي اللغة في العلوم والرياضيات.',
          links: [
            { text: 'شهادة معادلة AIU', href: 'HSCertificate/AIU%20CERTIFICATE.pdf' },
            { text: 'شهادة الثانوية العامة', href: 'HSCertificate/High%20school%20certificate%20.pdf' }
          ]
        },
        {
          badge: 'الشهادات',
          title: 'الشهادات المهنية',
          subtitle: 'تطوير المهارات التقنية',
          description: 'الحصول على شهادات متنوعة من مؤسسات مرموقة لتعزيز الأسس في البرمجة والتصميم.',
          links: [
            { text: 'أساسيات فيجما', href: 'OCC/Figma certificate.pdf' },
            { text: 'مقدمة في البرمجة (معهد بتس بيلاني)', href: 'OCC/ITP by bits.pdf' },
            { text: 'أساسيات بايثون (جامعة ميشيغان)', href: 'OCC/python by coursera.pdf' },
            { text: 'تقييم AWS (LearnTube)', href: 'OCC/LT AWS Assessment.png' }
          ]
        },
        {
          badge: '2026',
          title: '2026 — هدف التخرج ومسار البحث العلمي',
          subtitle: '29 أغسطس 2026',
          description: 'إتمام خط أنابيب ذكاء المستندات متعدد الوسائط على مستوى الإنتاج لمشروع التخرج في معهد بتس بيلاني بحلول 29 أغسطس. التوسع الفعّال في بنية VLM صفرية الطلقات وبروتوكولات فرض المخطط لسد الفجوة في معايير مستندات الخط العربي منخفضة الموارد. بناء محفظة بحثية تأسيسية للانتقال مباشرةً إلى برامج VSRP الممولة بالكامل ومسارات الماجستير/الدكتوراه المتكاملة.',
          milestones: [
            'خطوط الأنابيب متعددة الوسائط منشورة',
            'أطر تعليمات VLM مُتقنة',
            'جاهز لأدوار البحث المتقدم في الذكاء الاصطناعي والدراسات العليا'
          ]
        },
        {
          badge: '٢٠٢٢ — الحاضر',
          title: 'Growly Farms · مؤسس مشارك ومدير',
          subtitle: 'واندور، كيرالا، الهند · الزراعة العضوية',
          description: 'تأسست بالشراكة مع نبهان كي تي، Growly Farms مزرعة عضوية تمتد على ٥ أفدنة في واندور، كيرالا، تزرع الرامبوتان والجاكفروت وفاكهة التنين والبابايا والمزيد. تعمل المزرعة بأنظمة الري بالتنقيط الحديثة وأنظمة توصيل المغذيات الدقيقة من NETFM، تجمع بين المبادئ العضوية التقليدية والتكنولوجيا الزراعية الحديثة. رؤيتنا هي السياحة الزراعية التكنولوجية، والتوسع في الزراعة المائية، وذكاء المحاصيل المدعوم بالذكاء الاصطناعي — لجعل الزراعة أذكى وأخضر وأكثر إنتاجية.',
          milestones: [
            'مزرعة عضوية متعددة المحاصيل على ٥ أفدنة',
            'أنظمة الري بالتنقيط والمغذيات من NETFM منشورة',
            'الرؤية: سياحة زراعية تكنولوجية · زراعة مائية · تكامل الذكاء الاصطناعي'
          ],
          links: [
            { text: 'تابعنا على Instagram @growly.kl', href: 'https://www.instagram.com/growly.kl' }
          ]
        }
      ]
    },
    // Projects Section
    projects: {
      label: 'المحفظة',
      title: 'المشاريع والتجارب المختارة',
      subtitle: 'من الأنظمة الجاهزة للإنتاج إلى البناءات التجريبية، يمثل كل مشروع خطوة إلى الأمام في التميز التقني.',
      exploreAll: 'استكشف جميع المشاريع'
    },
    // Expertise Section
    expertise: {
      label: 'القدرات',
      title: 'المهارات واللغات والهوايات',
      languagesTitle: 'اللغات والتواصل',
      hobbiesTitle: 'الهوايات',
      filters: {
        all: 'الكل',
        frontend: 'الواجهة الأمامية',
        uiux: 'تصميم واجهة المستخدم',
        backend: 'الخلفية',
        mobile: 'أندرويد / iOS',
        ai: 'الذكاء الاصطناعي والسحابة',
        tools: 'الأدوات',
        soft: 'المهارات الناعمة',
        others: 'أخرى'
      }
    },
    // Connect Section
    connect: {
      label: 'التواصل',
      title: 'دعنا نبني شيئاً معاً',
      subtitle: 'منفتح على الفرص عن بُعد والهجينة. مرتاح في العمل عبر المناطق الزمنية في الهند والمملكة العربية السعودية.',
      getInTouch: 'تواصل معنا',
      email: 'البريد الإلكتروني',
      workEmail: 'البريد المهني',
      personalEmail: 'البريد الشخصي',
      phoneIN: 'الهاتف (الهند)',
      sendMessage: 'أرسل رسالة',
      name: 'الاسم',
      namePlaceholder: 'اسمك',
      emailPlaceholder: 'your.email@example.com',
      message: 'الرسالة',
      messagePlaceholder: 'رسالتك هنا...',
      category: 'الفئة',
      individual: 'فرد',
      company: 'شركة',
      other: 'أخرى',
      otherLabel: 'يرجى التحديد',
      otherPlaceholder: 'حدد فئتك',
      send: 'إرسال الرسالة'
    },
    // Footer
    footer: {
      navigation: 'التنقل',
      connect: 'المواقع',
      social: 'وسائل التواصل',
      status: 'الحالة',
      statusText: 'مهندس برمجيات مدعوم بالذكاء الاصطناعي | منفتح على الأدوار عن بُعد والهجينة والمحلية في الهند ودول مجلس التعاون الخليجي.',
      navLinks: {
        home: 'الرئيسية',
        about: 'نبذة',
        education: 'التعليم',
        projects: 'المشاريع',
        expertise: 'الخبرات',
        connect: 'التواصل'
      }
    },
    // Chatbot
    chatbot: {
      welcomeMessage: 'مرحباً! 👋 أنا مساعد محفظة اشفاق. اضغط على سؤال أدناه لمعرفة المزيد!',
      faqButtons: {
        about: 'نبذة عن اشفاق',
        finalProject: 'مشروع التخرج',
        education: 'التعليم',
        projects: 'المشاريع',
        skills: 'المهارات',
        contact: 'التواصل'
      },
      answers: {
        about: `<p><strong>اشفاق كي تي</strong> مطور Full-Stack موجّه نحو النتائج، <strong>مدعوم بالذكاء الاصطناعي</strong>، وطالب سنة أخيرة في بكالوريوس علوم الحاسوب من <strong>معهد بتس بيلاني</strong> (المعدل التراكمي 7.91)، يتخرج في أغسطس 2026.</p>
          <p>يمزج خبرته في <strong>مكدس MERN</strong> مع التكامل السحابي وتصميم UI/UX وسير العمل المدعومة بالذكاء الاصطناعي لبناء منصات رقمية سريعة وذكية وقابلة للتوسع.</p>
          <ul>
            <li>🏢 <strong>مؤسس ومدير تقني</strong> — آش تك سوليوشنز (2024–الحاضر)</li>
            <li>🌱 <strong>مؤسس مشارك ومدير</strong> — Growly Farms، كيرالا (2022–الحاضر)</li>
            <li>🎓 <strong>تطوير Full-Stack بالذكاء الاصطناعي</strong> — إنتراي إلفيت (2025–2026) · تقدير A+</li>
            <li>🌍 مرتاح للعمل في مناطق زمنية <strong>الهند ودول الخليج</strong></li>
            <li>🗣️ يتقن <strong>العربية والإنجليزية والمالايالامية</strong></li>
          </ul>
          <p>منفتح على أدوار <strong>عن بُعد وهجينة ومحلية</strong> في الهند ودول مجلس التعاون الخليجي. <a href="#about" onclick="navigateToPage('about'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">اقرأ المزيد →</a></p>`,

        education: `<p>📚 <strong>المسيرة الأكاديمية والمهنية:</strong></p>
          <ul>
            <li>🎓 <strong>بكالوريوس علوم الحاسوب — معهد بتس بيلاني</strong> (2023–2026)<br>برنامج أونلاين · المعدل التراكمي <strong>7.91</strong> · السنة الأخيرة · التخرج 29 أغسطس 2026</li>
            <li>💻 <strong>تطوير Full-Stack بالذكاء الاصطناعي — إنتراي إلفيت</strong> (2025–2026)<br>مكدس MERN · تقدير A+ · معتمد من إنتراي و NSDC · كوتشي</li>
            <li>🏫 <strong>مدرسة الشاطئ الثانوية</strong> — الدمام، المملكة العربية السعودية (2019–2021)<br>المسار العلمي · المعدل <strong>98%</strong> · وزارة التعليم السعودية</li>
          </ul>
          <p>📜 <strong>الشهادات:</strong> أساسيات فيجما · مقدمة في البرمجة (بتس) · Python (جامعة ميشيغان / Coursera) · تقييم AWS (LearnTube)</p>
          <p><a href="#education" onclick="navigateToPage('education'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">عرض الجدول الزمني الكامل والشهادات →</a></p>`,

        projects: `<p>🚀 لدى اشفاق <strong>أكثر من 20 مشروعاً</strong> تغطي Full-Stack والذكاء الاصطناعي والبيانات والأنظمة والتصميم:</p>
          <ul>
            <li>🛍️ <strong>Basket Store</strong> — تجارة إلكترونية MERN + دردشة ورؤى بـ Gemini AI</li>
            <li>📖 <strong>StudyBuddy</strong> — منصة تعليمية متكاملة · JWT · تلخيص AI · بومودورو · لوحة تحليلات</li>
            <li>🌐 <strong>آش تك سوليوشنز</strong> — موقع وكالة حي · روبوت محادثة AI · خلفية Serverless</li>
            <li>🏦 <strong>نظام Banking gRPC</strong> — Python · SQL · gRPC · طبقات المصادقة · محرك معاملات</li>
            <li>☁️ <strong>تكامل AWS RDS</strong> — مخططات DB للإنتاج · نسخ احتياطي تلقائي · توفر عالٍ</li>
            <li>📊 <strong>لوحات Tableau</strong> — تحليل الصحة العقلية · تسعير Airbnb وتحليل الإشغال</li>
            <li>⚙️ <strong>سير عمل DevOps</strong> — Git · Docker · Flask · خط CI/CD</li>
            <li>🖥️ <strong>عميل HTTP بلغة C</strong> — مقابس TCP خام · برمجة بروتوكولات الشبكة</li>
            <li>📱 <strong>تصميم UI/UX لتطبيق ETTI</strong> — نموذج تطبيق توصيل متعدد الخدمات · iPad</li>
            <li>🐍 <strong>تحليل بيانات لاعبي كرة القدم</strong> — Python · Pandas · EDA · تقييم السوق</li>
          </ul>
          <p><a href="#projects" onclick="navigateToPage('projects'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">استعرض جميع المشاريع →</a> · <a href="https://github.com/ashfaaqkt" target="_blank">GitHub ↗</a></p>`,

        skills: `<p>💡 <strong>ملخص المهارات الكامل من السيرة الذاتية:</strong></p>
          <ul>
            <li>⚛️ <strong>الواجهة الأمامية:</strong> React · HTML5 · CSS3 · JavaScript · تصميم متجاوب · رسوم متحركة · UI/UX</li>
            <li>🎨 <strong>تصميم:</strong> Figma · Adobe XD · MockUp (iPad) · Canva Pro · DaVinci Resolve · PicsArt</li>
            <li>🔧 <strong>الخلفية:</strong> Node.js · Express.js · Python · Flask · gRPC · لغة C</li>
            <li>🗄️ <strong>قواعد البيانات:</strong> MongoDB · MySQL · AWS RDS · Firebase</li>
            <li>📱 <strong>الجوال:</strong> Kotlin · Swift · Android Studio</li>
            <li>🤖 <strong>الذكاء الاصطناعي والسحابة:</strong> هندسة المطالبات LLM · Gemini API · التطوير بالذكاء الاصطناعي · تحليل البيانات</li>
            <li>🛠️ <strong>الأدوات:</strong> Git · GitHub · Docker · Tableau · Cursor IDE · VS Code · Replit · Framer · Notion · Linux</li>
            <li>🌿 <strong>أخرى:</strong> التصميم الداخلي · SketchUp / 5D Planner · AutoCAD · الزراعة الحديثة · تقنيات الزراعة</li>
          </ul>
          <p><a href="#expertise" onclick="navigateToPage('expertise'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">استكشف الخبرات الكاملة →</a></p>`,

        contact: `<p>📬 <strong>تواصل مع اشفاق:</strong></p>
          <ul>
            <li>💼 <strong>البريد المهني:</strong> <a href="mailto:hire.me@ashfaaqkt.com">hire.me@ashfaaqkt.com</a></li>
            <li>📧 <strong>البريد الشخصي:</strong> <a href="mailto:ashfaaqktmail@gmail.com">ashfaaqktmail@gmail.com</a></li>
            <li>📞 <strong>الهاتف (الهند):</strong> <a href="tel:+919995032407">+91 99950 32407</a></li>
            <li>💬 <strong>WhatsApp:</strong> <a href="https://wa.me/919995032407?text=Hello%20Ashfaaq" target="_blank">تواصل عبر واتساب ↗</a></li>
            <li>🏢 <strong>آش تك:</strong> <a href="https://www.ashtechnologiesolutions.com/" target="_blank">ashtechnologiesolutions.com ↗</a></li>
            <li>💻 <strong>GitHub:</strong> <a href="https://github.com/ashfaaqkt" target="_blank">github.com/ashfaaqkt ↗</a></li>
          </ul>
          <p>منفتح على أدوار <strong>عن بُعد وهجينة ومحلية</strong> في الهند ودول مجلس التعاون الخليجي. <a href="#connect" onclick="navigateToPage('connect'); setTimeout(() => document.getElementById('chatbot-minimize').click(), 500);">أرسل رسالة →</a></p>`,

        finalProject: `<p>🎓 <strong>مشروع التخرج النهائي — معهد بتس بيلاني</strong></p>
          <p><strong>نظام المكافآت والذكاء المعتمد على مسح الفواتير</strong></p>
          <ul>
            <li>🧠 <strong>التقنيات:</strong> MERN · Firebase · Python · Gemini API · تعلم الآلة · React</li>
            <li>📄 <strong>ما يفعله:</strong> يمسح الفواتير باستخدام رؤية الذكاء الاصطناعي، يستخرج بيانات منظمة (المنتجات، الإجماليات، البائع) عبر Google Gemini API، ويشغّل محرك مكافآت وولاء ديناميكي للمستخدمين.</li>
            <li>⚙️ <strong>البنية:</strong> خط أنابيب AI متعدد الوسائط · استخراج مستندات بدون أمثلة · Firebase Serverless · منطق مكافآت قابل للتوسع</li>
            <li>🏆 <strong>المرحلة:</strong> PoC المرحلة الثالثة — فريق ARAJ · بناء على مستوى الإنتاج</li>
            <li>📅 <strong>هدف التخرج:</strong> 29 أغسطس 2026 — استهداف برامج VSRP ومسارات الماجستير/الدكتوراه في الذكاء الاصطناعي</li>
          </ul>
          <p><a href="https://github.com/ashfaaqkt/Bill-Scanning-Based-Reward-Intelligence-System-study-project-bits-poc-phase-3-Team-ARAJ" target="_blank">مستودع GitHub ↗</a> &nbsp;·&nbsp; <a href="https://ashfaaqkt.github.io/Bill-Scanning-Based-Reward-Intelligence-System-study-project-bits-poc-phase-3-Team-ARAJ/public/index.html" target="_blank">عرض مباشر ↗</a></p>`
      }
    }
  }
};

// Expose on window so chatbot and any inline handlers can access translations
window.translations = translations;

// ============================================
// INITIALIZATION
// ============================================

// Safe initializer to prevent one failing module from breaking others
function safeInit(name, fn) {
  try {
    if (typeof fn === 'function') {
      fn();
    }
  } catch (err) {
    // Log to console so debugging is easier, but don't block other features
    console.error(`Error during init: ${name}`, err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  // Add js-ready class to enable animation hiding as early as possible
  document.documentElement.classList.add('js-ready');

  // Initialize auth first for state and PDF protection
  safeInit('auth', initAuth);
  
  // Initialize language system
  safeInit('language', initLanguageSystem);
  safeInit('themeToggle', initThemeToggle);

  // Initialize in proper order to prevent flicker
  safeInit('navigation', initNavigation);
  // Re-measure nav height now that DOM is fully initialized and fonts are likely applied
  syncNavHeight();
  safeInit('anchorLinks', initAnchorLinks);
  safeInit('particles', initParticleCanvas);
  safeInit('scrollProgress', initScrollProgress);
  safeInit('backToTop', initBackToTop);
  safeInit('contactForm', initContactForm);
  safeInit('chatbot', initChatbot);
  safeInit('portfolioSummaryModal', initPortfolioSummaryModal);
  safeInit('fypModal', initFYPModal);

  // Initialize animations
  initScrollAnimations();
  populateDynamicContent();

  // Auto-scroll hint for About page card carousel (mobile only)
  const aboutContentGrid = document.querySelector('#page-about .content-grid');
  if (aboutContentGrid) {
    createAutoScroller(aboutContentGrid, { speed: 0.3, pauseMs: 3000, startDelayMs: 2000 });
  }

  // Fallback: Ensure animated elements become visible after a delay
  // in case IntersectionObserver fails or elements are already in viewport
  setTimeout(() => {
    const animatedElements = document.querySelectorAll('[data-animate]:not(.animated)');
    animatedElements.forEach((el, index) => {
      const delay = parseInt(el.getAttribute('data-delay')) || 0;
      setTimeout(() => {
        if (!el.classList.contains('animated')) {
          el.classList.add('animated');
          animatedElementsSet.add(el);
        }
      }, delay + (index * 50));
    });
  }, 1000);

  // PDF interception moved to top of file for early protection

  // Show sign-in hint on launch if not authenticated
  function maybeShowSignInHint() {
    const token = localStorage.getItem('portfolio_token');
    const isValid = token && token !== 'null' && token !== 'undefined' && token.length > 20;
    if (!isValid) showSignInHintToast();
  }
  setTimeout(maybeShowSignInHint, 2500);

  // Re-show hint when user switches language — but skip the first languageChanged
  // event which is fired by initLanguageSystem's startup setLanguage call
  let _skipFirstLangChange = true;
  document.addEventListener('languageChanged', () => {
    if (_skipFirstLangChange) { _skipFirstLangChange = false; return; }
    maybeShowSignInHint();
  });
});


// ============================================
// THEME SYSTEM
// ============================================

function initThemeToggle() {
  const btns = [
    document.getElementById('theme-toggle-btn'),
    document.getElementById('msm-theme-btn')
  ].filter(Boolean);

  if (btns.length === 0) return;

  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      const isLight = document.documentElement.getAttribute('data-theme') === 'light';
      const newTheme = isLight ? 'dark' : 'light';

      // Smooth transition: briefly add class so all elements animate theme properties
      document.documentElement.classList.add('theme-switching');
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('portfolio-theme', newTheme);
      setTimeout(() => document.documentElement.classList.remove('theme-switching'), 400);
    });
  });
}

// ============================================
// NAVIGATION SYSTEM
// ============================================

// Sync the real nav height into --nav-total-height so padding-top is exact.
// On mobile the sub-nav is absolute, so offsetHeight returns only the top row.
function syncNavHeight() {
  const nav = document.getElementById('main-nav');
  if (!nav) return;
  document.documentElement.style.setProperty('--nav-total-height', nav.offsetHeight + 'px');
}
// Run immediately and on every resize/font-load
syncNavHeight();
window.addEventListener('resize', syncNavHeight, { passive: true });
document.fonts?.ready?.then(syncNavHeight);

function initNavigation() {
  const nav = document.getElementById('main-nav');
  const navToggle = document.getElementById('nav-toggle');
  const navMenu = document.getElementById('nav-menu');
  const navLinks = document.querySelectorAll('.nav-link, .msm-link');
  const sections = document.querySelectorAll('.page');
  let activeSectionId = 'home';

  // Handle scroll effect on nav with throttling
  let navTicking = false;

  window.addEventListener('scroll', () => {
    if (!navTicking) {
      window.requestAnimationFrame(() => {
        const currentScroll = window.pageYOffset;

        if (currentScroll > 100) {
          nav.classList.add('scrolled');
        } else {
          nav.classList.remove('scrolled');
        }

        // Scrollspy: update active nav item based on current section in view
        const navHeight = nav?.offsetHeight || 80;
        const scrollPosition = currentScroll + navHeight + 1;
        let newActiveId = activeSectionId;

        sections.forEach(section => {
          const sectionTop = section.offsetTop;
          const sectionBottom = sectionTop + section.offsetHeight;
          if (scrollPosition >= sectionTop && scrollPosition < sectionBottom) {
            newActiveId = section.getAttribute('data-page') || newActiveId;
          }
        });

        if (newActiveId !== activeSectionId) {
          activeSectionId = newActiveId;
          navLinks.forEach(link => {
            const linkPage = link.getAttribute('data-page');
            link.classList.toggle('active', linkPage === activeSectionId);
          });
        }

        navTicking = false;
      });
      navTicking = true;
    }
  });

  // Mobile menu toggle
  const appContainer = document.getElementById('app-container');

  function openMobileSideMenu() {
    document.documentElement.classList.add('menu-open');
    if (navToggle) navToggle.classList.add('active');
  }

  function closeMobileSideMenu() {
    document.documentElement.classList.remove('menu-open');
    if (navToggle) navToggle.classList.remove('active');
  }

  window.closeMobileSideMenu = closeMobileSideMenu;

  if (navToggle) {
    navToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = document.documentElement.classList.contains('menu-open');
      if (isOpen) {
        closeMobileSideMenu();
      } else {
        openMobileSideMenu();
      }
    });
  }

  const msmCloseBtn = document.getElementById('msm-close-btn');
  if (msmCloseBtn) {
    msmCloseBtn.addEventListener('click', () => {
      closeMobileSideMenu();
    });
  }

  // Close menu when clicking outside on the minimized app-container
  if (appContainer) {
    appContainer.addEventListener('click', (e) => {
      if (document.documentElement.classList.contains('menu-open')) {
        e.preventDefault();
        e.stopPropagation();
        closeMobileSideMenu();
      }
    });
  }

  // Close menu when clicking outside the navbar
  document.addEventListener('click', (e) => {
    const mobileSideMenu = document.getElementById('mobile-side-menu');
    const isClickInsideMenu = mobileSideMenu && mobileSideMenu.contains(e.target);
    const isClickInsideToggle = navToggle && navToggle.contains(e.target);
    
    if (!isClickInsideMenu && !isClickInsideToggle && document.documentElement.classList.contains('menu-open')) {
      closeMobileSideMenu();
    }
  });

  // Handle navigation clicks
  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const targetPage = link.getAttribute('data-page');
      navigateToPage(targetPage);
      closeMobileSideMenu();
    });
  });

  // CV Modal functionality
  initCVModal();

  // Initial page load: ensure we start at home without relying on URL hash
  navigateToPage('home');
}

function navigateToPage(pageId) {
  const navLinks = document.querySelectorAll('.nav-link');
  const targetId = pageId || 'home';

  // FYP is a sub-section inside the projects page (id="fyp"), not a full .page
  const targetSection = targetId === 'fyp'
    ? document.getElementById('fyp')
    : document.querySelector(`#page-${targetId}`);

  if (!targetSection) {
    console.warn('Target section not found:', targetId);
    return;
  }

  // Smooth scroll to the corresponding section instead of hiding/showing pages
  const navHeight = document.getElementById('main-nav')?.offsetHeight || 80;
  const targetPosition = targetSection.getBoundingClientRect().top + window.pageYOffset - navHeight;

  window.scrollTo({
    top: Math.max(0, targetPosition),
    behavior: 'smooth'
  });

  // Update active nav link highlight
  navLinks.forEach(link => {
    link.classList.toggle('active', link.getAttribute('data-page') === targetId);
  });

  // Trigger animations for newly visible section (kept for consistency)
  // Ensure header highlights correctly
  syncNavHeight();
}

// Make navigateToPage globally accessible for onclick handlers
window.navigateToPage = navigateToPage;

// ============================================
// TOAST NOTIFICATIONS
// ============================================
function getGreeting(lang) {
  const h = new Date().getHours();
  if (lang === 'ar') {
    if (h < 5)  return 'ليلة طيبة';
    if (h < 12) return 'صباح الخير';
    if (h < 17) return 'مساء الخير';
    if (h < 21) return 'مساء النور';
    return 'ليلة سعيدة';
  }
  if (h < 5)  return 'Good Night';
  if (h < 12) return 'Good Morning';
  if (h < 17) return 'Good Afternoon';
  if (h < 21) return 'Good Evening';
  return 'Good Night';
}

function showToast({ title, sub = '', icon = '👋', type = 'welcome', duration = 5000, onRender = null }) {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    document.body.appendChild(container);
  }

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon" aria-hidden="true">${icon}</span>
    <div class="toast-body">
      <div class="toast-title">${title}</div>
      ${sub ? `<div class="toast-sub">${sub}</div>` : ''}
    </div>
    <button class="toast-close" aria-label="Dismiss">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" width="12" height="12">
        <path d="M18 6L6 18M6 6l12 12"/>
      </svg>
    </button>
    <div class="toast-progress"><div class="toast-progress-bar"></div></div>
  `;
  container.appendChild(toast);
  if (onRender) onRender(toast);

  // Animate in
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      toast.classList.add('toast-visible');
      const bar = toast.querySelector('.toast-progress-bar');
      if (bar) {
        bar.style.transition = `transform ${duration}ms linear`;
        bar.style.transform = 'scaleX(0)';
      }
    });
  });

  // Auto-hide
  const hideTimer = setTimeout(() => dismissToast(toast), duration);

  function dismissToast(t) {
    clearTimeout(hideTimer);
    t.classList.remove('toast-visible');
    t.classList.add('toast-hiding');
    t.addEventListener('transitionend', () => t.remove(), { once: true });
  }

  // Manual dismiss via X button
  const closeBtn = toast.querySelector('.toast-close');
  if (closeBtn) closeBtn.addEventListener('click', () => dismissToast(toast));
}

function showWelcomeToast(firstName, isNew = false) {
  const lang = currentLanguage || 'en';
  const greeting = getGreeting(lang);
  const isAr = lang === 'ar';
  const title = isAr
    ? (isNew ? `مرحباً ${firstName}! 🎉` : `أهلاً بعودتك، ${firstName}! 🎉`)
    : (isNew ? `Welcome, ${firstName}! 🎉` : `Welcome back, ${firstName}! 🎉`);
  showToast({
    title,
    sub: greeting,
    icon: '✨',
    type: 'welcome',
    duration: 5000
  });
}

function showGoodbyeToast(firstName) {
  const lang = currentLanguage || 'en';
  const isAr = lang === 'ar';
  showToast({
    title: isAr ? `وداعاً ${firstName}!` : `Goodbye, ${firstName}!`,
    sub: isAr ? 'أتمنى لك يوماً رائعاً 😊' : 'Have a nice day 😊',
    icon: '👋',
    type: 'bye',
    duration: 4000
  });
}

function showSignInHintToast() {
  // Remove any existing hint toast before showing a new one
  document.querySelectorAll('.toast.toast-hint').forEach(t => t.remove());

  const lang = currentLanguage || 'en';
  const isAr = lang === 'ar';
  const linkLabel = isAr ? 'سجّل الدخول الآن ←' : 'Sign in now →';
  const subText = isAr
    ? `انضم لعرض وتنزيل ملفات السيرة الذاتية والشهادات<br><button class="toast-link" data-toast-action="signin">${linkLabel}</button>`
    : `Join to view & download CVs and certificates<br><button class="toast-link" data-toast-action="signin">${linkLabel}</button>`;

  showToast({
    title: isAr ? 'قم بتسجيل الدخول للوصول الكامل' : 'Sign in for full access to files',
    sub: subText,
    icon: '🔒',
    type: 'hint',
    duration: 8000,
    onRender(toast) {
      const btn = toast.querySelector('[data-toast-action="signin"]');
      if (btn) {
        btn.addEventListener('click', () => {
          toast.classList.remove('toast-visible');
          toast.classList.add('toast-hiding');
          toast.addEventListener('transitionend', () => toast.remove(), { once: true });
          if (typeof window.openAuthModal === 'function') window.openAuthModal('login');
        });
      }
    }
  });
}

function initCVModal() {
  const cvModalBtn = document.getElementById('cv-modal-btn');
  const cvModalOverlay = document.getElementById('cv-modal-overlay');
  const cvModalClose = document.getElementById('cv-modal-close');

  if (!cvModalBtn || !cvModalOverlay) return;

  function openModal() {
    cvModalOverlay.classList.add('active');
    cvModalOverlay.setAttribute('aria-hidden', 'false');
    document.body.classList.add('no-scroll');
    document.documentElement.classList.add('no-scroll');
  }

  function closeModal() {
    cvModalOverlay.classList.remove('active');
    cvModalOverlay.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('no-scroll');
    document.documentElement.classList.remove('no-scroll');
  }

  window.openCVModal = openModal;

  cvModalBtn.addEventListener('click', openModal);

  if (cvModalClose) {
    cvModalClose.addEventListener('click', closeModal);
  }

  // Close on overlay backdrop click
  cvModalOverlay.addEventListener('click', (e) => {
    if (e.target === cvModalOverlay) closeModal();
  });

  // Close on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && cvModalOverlay.classList.contains('active')) {
      closeModal();
    }
  });

  // Update modal text based on language
  updateCVModalLabels();
  document.addEventListener('languageChanged', updateCVModalLabels);
}

function updateCVModalLabels() {
  const lang = currentLanguage || 'en';
  const modal = document.getElementById('cv-modal');
  if (!modal) return;

  modal.querySelectorAll('[data-en]').forEach(el => {
    const text = el.getAttribute(`data-${lang}`) || el.getAttribute('data-en');
    if (text && el.children.length === 0) {
      el.textContent = text;
    }
  });
}


// ============================================
// LANGUAGE SYSTEM
// ============================================

function initLanguageSystem() {
  const btns = [
    document.getElementById('lang-toggle'),
    document.getElementById('msm-lang-btn')
  ].filter(Boolean);

  if (btns.length === 0) return;

  // Set initial language - use a small delay to ensure DOM is fully ready
  setTimeout(() => {
    setLanguage(currentLanguage);
  }, 50);

  // Toggle language on button click
  btns.forEach(btn => {
    btn.addEventListener('click', () => {
      const newLang = currentLanguage === 'en' ? 'ar' : 'en';
      switchLanguage(newLang);
    });
  });
}

function switchLanguage(newLang) {
  if (newLang === currentLanguage) return;

  // Update currentLanguage BEFORE calling setLanguage so populateTimeline uses correct language
  currentLanguage = newLang;
  localStorage.setItem('portfolio-language', newLang);
  window.currentLanguage = newLang;

  // Add transition class for animation
  document.body.classList.add('language-transitioning');

  // Wait for animation to start
  setTimeout(() => {
    setLanguage(newLang);

    // Remove transition class after content is updated
    setTimeout(() => {
      document.body.classList.remove('language-transitioning');
    }, 300);
  }, 150);
}

function setLanguage(lang) {
  const t = translations[lang];
  if (!t) return;

  // Set document direction
  document.documentElement.setAttribute('dir', lang === 'ar' ? 'rtl' : 'ltr');
  document.documentElement.setAttribute('lang', lang);

  // Update language toggle tooltip text + accessibility label
  const langToggle = document.getElementById('lang-toggle');
  if (langToggle) {
    const tooltip = langToggle.querySelector('.lang-tooltip');
    if (lang === 'en') {
      langToggle.setAttribute('aria-label', 'العربية');
      if (tooltip) tooltip.textContent = 'العربية';
    } else {
      langToggle.setAttribute('aria-label', 'English');
      if (tooltip) tooltip.textContent = 'English';
    }
  }

  const msmLangBtn = document.getElementById('msm-lang-btn');
  if (msmLangBtn) {
    msmLangBtn.setAttribute('aria-label', lang === 'en' ? 'العربية' : 'English');
  }

  // Notify any listeners (e.g., CV dropdown) that language has changed
  try {
    document.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));
  } catch (e) {
    // Fallback for very old browsers without CustomEvent constructor
    const event = document.createEvent && document.createEvent('Event');
    if (event) {
      event.initEvent('languageChanged', true, true);
      document.dispatchEvent(event);
    }
  }

  // Update navigation links
  document.querySelectorAll('.nav-link-text').forEach((link, index) => {
    const keys = ['home', 'about', 'education', 'projects', 'fyp', 'expertise', 'connect'];
    if (keys[index]) {
      link.textContent = t.nav[keys[index]];
    }
  });

  // Update hero section - try multiple selector strategies
  const heroGreetingText = document.querySelector('#page-home .hero-greeting .hero-greeting-text') || document.querySelector('.hero-greeting .hero-greeting-text');
  if (heroGreetingText) {
    heroGreetingText.textContent = t.hero.greeting;
  }

  const titleLine = document.querySelector('#page-home .hero-title .title-line') || document.querySelector('.hero-title .title-line');
  if (titleLine) {
    titleLine.textContent = t.hero.name;
  }

  const heroDegreeText = document.querySelector('#page-home .hero-degree .hero-degree-text') || document.querySelector('.hero-degree .hero-degree-text');
  if (heroDegreeText) {
    heroDegreeText.textContent = t.hero.degree;
  }

  const heroDescription = document.querySelector('#page-home .hero-description') || document.querySelector('.hero-description');
  if (heroDescription) {
    heroDescription.textContent = t.hero.description;
  }

  const statLabels = document.querySelectorAll('#page-home .stat-label');
  const statLabelsFallback = statLabels.length >= 4 ? statLabels : document.querySelectorAll('.stat-label');
  if (statLabelsFallback.length >= 4) {
    statLabelsFallback[0].textContent = t.hero.cgpa;
    statLabelsFallback[1].textContent = t.hero.graduation;
    statLabelsFallback[2].textContent = t.hero.languages;
    statLabelsFallback[3].textContent = t.hero.projects;
  }

  const heroQuote = document.querySelector('#page-home .hero-quote p') || document.querySelector('.hero-quote p');
  if (heroQuote) {
    heroQuote.textContent = t.hero.quote;
  }

  // Generic text elements with data-en / data-ar attributes (e.g., mobile contact buttons)
  document.querySelectorAll('[data-en][data-ar]').forEach(el => {
    const text = el.getAttribute(lang === 'ar' ? 'data-ar' : 'data-en');
    if (!text) return;
    /* Elements marked data-html="true" may contain safe markup (e.g. links) */
    if (el.dataset.html === 'true') el.innerHTML = text;
    else el.textContent = text;
  });

  // Update placeholders
  document.querySelectorAll('[data-placeholder-en][data-placeholder-ar]').forEach(el => {
    const placeholder = el.getAttribute(lang === 'ar' ? 'data-placeholder-ar' : 'data-placeholder-en');
    if (placeholder) el.setAttribute('placeholder', placeholder);
  });

  // Update custom select triggers if they have a selected value
  document.querySelectorAll('.custom-select').forEach(cs => {
    const hiddenInput = cs.querySelector('input[type="hidden"]');
    const triggerSpan = cs.querySelector('.custom-select-trigger span');
    if (hiddenInput && hiddenInput.value && triggerSpan) {
      const selectedOption = cs.querySelector(`.custom-option[data-value="${hiddenInput.value}"]`);
      if (selectedOption) {
        triggerSpan.textContent = selectedOption.getAttribute(lang === 'ar' ? 'data-ar' : 'data-en') || selectedOption.textContent;
      }
    }
  });

  // Ensure 'Sign in' / 'Hello $user!' text is correct
  if (typeof window.updateAuthLangState === 'function') {
    window.updateAuthLangState();
  }

  // Update about section
  const aboutLabel = document.querySelector('#page-about .page-label');
  if (aboutLabel) aboutLabel.textContent = t.about.label;

  const aboutTitle = document.querySelector('#page-about .page-title');
  if (aboutTitle) aboutTitle.textContent = t.about.title;

  const aboutSubtitle = document.querySelector('#page-about .page-subtitle');
  if (aboutSubtitle) aboutSubtitle.textContent = t.about.subtitle;

  const techLabel = document.querySelector('.tech-label');
  if (techLabel) techLabel.textContent = t.about.techStack;

  // Update about cards
  const aboutCards = document.querySelectorAll('#page-about .content-card');
  if (aboutCards.length >= 3) {
    const card1Title = aboutCards[0].querySelector('h3');
    const card1Desc = aboutCards[0].querySelector('p');
    if (card1Title) {
      card1Title.innerHTML = t.about.card1.title + '<br><span style="font-size: 0.85rem; color: var(--color-text-secondary); font-weight: 400;">' + t.about.card1.subtitle + '</span>';
    }
    if (card1Desc) card1Desc.textContent = t.about.card1.description;

    const card2Title = aboutCards[1].querySelector('h3');
    const card2Desc = aboutCards[1].querySelector('p');
    if (card2Title) {
      card2Title.innerHTML = t.about.card2.title + '<br><span style="font-size: 0.85rem; color: var(--color-text-secondary); font-weight: 400;">' + t.about.card2.subtitle + '</span>';
    }
    if (card2Desc) card2Desc.textContent = t.about.card2.description;

    const card3Title = aboutCards[2].querySelector('h3');
    const card3Desc = aboutCards[2].querySelector('p');
    if (card3Title) {
      card3Title.innerHTML = t.about.card3.title + '<br><span style="font-size: 0.85rem; color: var(--color-text-secondary); font-weight: 400;">' + t.about.card3.subtitle + '</span>';
    }
    if (card3Desc) card3Desc.textContent = t.about.card3.description;
  }

  // Update education section
  const eduLabel = document.querySelector('#page-education .page-label');
  if (eduLabel) eduLabel.textContent = t.education.label;

  const eduTitle = document.querySelector('#page-education .page-title');
  if (eduTitle) eduTitle.textContent = t.education.title;

  // Update projects section
  const projLabel = document.querySelector('#page-projects .page-label');
  if (projLabel) projLabel.textContent = t.projects.label;

  const projTitle = document.querySelector('#page-projects .page-title');
  if (projTitle) projTitle.textContent = t.projects.title;

  const projSubtitle = document.querySelector('#page-projects .page-subtitle');
  if (projSubtitle) projSubtitle.textContent = t.projects.subtitle;

  const exploreBtn = document.querySelector('.projects-cta .btn-outline span');
  if (exploreBtn) exploreBtn.textContent = t.projects.exploreAll;

  // Update expertise section
  const expLabel = document.querySelector('#page-expertise .page-label');
  if (expLabel) expLabel.textContent = t.expertise.label;

  const expTitle = document.querySelector('#page-expertise .page-title');
  if (expTitle) expTitle.textContent = t.expertise.title;

  const langTitle = document.querySelector('.languages-section .section-subtitle');
  if (langTitle) langTitle.textContent = t.expertise.languagesTitle;

  const hobbiesTitle = document.querySelector('.hobbies-section .section-subtitle');
  if (hobbiesTitle) hobbiesTitle.textContent = t.expertise.hobbiesTitle;

  // Update connect section
  const connectLabel = document.querySelector('#page-connect .page-label');
  if (connectLabel) connectLabel.textContent = t.connect.label;

  const connectTitle = document.querySelector('#page-connect .page-title');
  if (connectTitle) connectTitle.textContent = t.connect.title;

  const connectSubtitle = document.querySelector('#page-connect .page-subtitle');
  if (connectSubtitle) connectSubtitle.textContent = t.connect.subtitle;

  const getInTouch = document.querySelector('.contact-info-card h3');
  if (getInTouch) getInTouch.textContent = t.connect.getInTouch;

  const contactLabels = document.querySelectorAll('.contact-item .contact-label');
  if (contactLabels[0]) contactLabels[0].textContent = t.connect.workEmail;
  if (contactLabels[1]) contactLabels[1].textContent = t.connect.personalEmail;
  if (contactLabels[2]) contactLabels[2].textContent = t.connect.phoneIN;

  const sendMessageTitle = document.querySelector('.contact-form-card h3');
  if (sendMessageTitle) sendMessageTitle.textContent = t.connect.sendMessage;

  const nameLabel = document.querySelector('label[for="name"]');
  if (nameLabel) nameLabel.textContent = t.connect.name;

  const nameInput = document.getElementById('name');
  if (nameInput) nameInput.placeholder = t.connect.namePlaceholder;

  const emailLabelForm = document.querySelector('label[for="email"]');
  if (emailLabelForm) emailLabelForm.textContent = t.connect.email;

  const emailInput = document.getElementById('email');
  if (emailInput) emailInput.placeholder = t.connect.emailPlaceholder;

  const messageLabel = document.querySelector('label[for="message"]');
  if (messageLabel) messageLabel.textContent = t.connect.message;

  const messageTextarea = document.getElementById('message');
  if (messageTextarea) messageTextarea.placeholder = t.connect.messagePlaceholder;

  const categoryLabel = document.querySelector('.form-label');
  if (categoryLabel) categoryLabel.textContent = t.connect.category;

  const checkboxLabels = document.querySelectorAll('.checkbox-text');
  if (checkboxLabels.length >= 3) {
    checkboxLabels[0].textContent = t.connect.individual;
    checkboxLabels[1].textContent = t.connect.company;
    checkboxLabels[2].textContent = t.connect.other;
  }

  const otherInput = document.getElementById('other-detail');
  if (otherInput) otherInput.placeholder = t.connect.otherPlaceholder;

  const sendBtn = document.querySelector('#contact-form button[type="submit"] span');
  if (sendBtn) sendBtn.textContent = t.connect.send;

  // Footer text updated via data-en/data-ar generic handler above

  // Re-populate dynamic content with new language
  if (typeof populateDynamicContent === 'function') {
    // Clear existing dynamic content
    const dynamicContainers = ['tech-list', 'timeline', 'projects-grid', 'skills-grid', 'skills-filters', 'languages-list', 'hobbies-list'];
    dynamicContainers.forEach(id => {
      const container = document.getElementById(id);
      if (container) container.innerHTML = '';
    });

    // Re-populate
    populateDynamicContent();
  }

  // Update chatbot language if it exists
  if (typeof window.updateChatbotLanguage === 'function') {
    window.updateChatbotLanguage();
  }
}

// ============================================
// PARTICLE CANVAS
// ============================================

function initParticleCanvas() {
  const canvas = document.getElementById('particle-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let animationId;

  // Set canvas size
  function resizeCanvas() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }

  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  // Particle system
  const particles = [];
  const particleCount = 50;

  class Particle {
    constructor() {
      this.reset();
    }

    reset() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.size = Math.random() * 2 + 0.5;
      this.speedX = (Math.random() - 0.5) * 0.5;
      this.speedY = (Math.random() - 0.5) * 0.5;
      this.opacity = Math.random() * 0.5 + 0.2;
    }

    update() {
      this.x += this.speedX;
      this.y += this.speedY;

      if (this.x < 0 || this.x > canvas.width) this.speedX *= -1;
      if (this.y < 0 || this.y > canvas.height) this.speedY *= -1;
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fillStyle = `rgba(59, 130, 246, ${this.opacity})`;
      ctx.fill();
    }
  }

  // Create particles
  for (let i = 0; i < particleCount; i++) {
    particles.push(new Particle());
  }

  // Draw connections
  function drawConnections() {
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const distance = Math.sqrt(dx * dx + dy * dy);

        if (distance < 150) {
          ctx.beginPath();
          ctx.strokeStyle = `rgba(59, 130, 246, ${0.1 * (1 - distance / 150)})`;
          ctx.lineWidth = 0.5;
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
  }

  // Animation loop
  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    particles.forEach(particle => {
      particle.update();
      particle.draw();
    });

    drawConnections();

    animationId = requestAnimationFrame(animate);
  }

  animate();
}

// ============================================
// SCROLL ANIMATIONS
// ============================================

// Global animation observer to prevent duplicates
let globalAnimationObserver = null;
const animatedElementsSet = new Set();

function initScrollAnimations() {
  // Create observer if it doesn't exist
  if (!globalAnimationObserver) {
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    globalAnimationObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        // Prevent re-animation of already animated elements
        if (entry.isIntersecting && !animatedElementsSet.has(entry.target)) {
          animatedElementsSet.add(entry.target);

          // Use requestAnimationFrame for smoother animations
          requestAnimationFrame(() => {
            // Check if element has data-animate attribute (uses 'animated' class)
            if (entry.target.hasAttribute('data-animate')) {
              const delay = parseInt(entry.target.getAttribute('data-delay')) || 0;
              setTimeout(() => {
                entry.target.classList.add('animated');
              }, delay);
            }
            // Otherwise, it's a timeline item, project card, or skill card (uses 'visible' class)
            else {
              entry.target.classList.add('visible');
            }
          });

          // Unobserve after animation starts
          globalAnimationObserver.unobserve(entry.target);
        }
      });
    }, observerOptions);
  }

  // Observe all elements with data-animate attribute
  const animatedElements = document.querySelectorAll('[data-animate]');
  animatedElements.forEach(el => {
    // Only observe if not already animated
    if (!animatedElementsSet.has(el)) {
      el.classList.remove('animated');

      // Check if element is already in viewport - animate immediately
      const rect = el.getBoundingClientRect();
      const isInViewport = rect.top < window.innerHeight && rect.bottom > 0;

      if (isInViewport) {
        const delay = parseInt(el.getAttribute('data-delay')) || 0;
        setTimeout(() => {
          el.classList.add('animated');
          animatedElementsSet.add(el);
        }, delay);
      } else {
        globalAnimationObserver.observe(el);
      }
    }
  });

  // Also observe timeline items, project cards, and skill cards
  const scrollItems = document.querySelectorAll('.timeline-item:not(.visible), .project-card:not(.visible), .skill-card:not(.visible)');
  scrollItems.forEach(item => {
    if (!animatedElementsSet.has(item)) {
      globalAnimationObserver.observe(item);
    }
  });
}


// ============================================
// SCROLL PROGRESS
// ============================================

function initScrollProgress() {
  const progressBar = document.getElementById('scroll-progress');
  if (!progressBar) return;

  let ticking = false;

  window.addEventListener('scroll', () => {
    if (!ticking) {
      window.requestAnimationFrame(() => {
        const windowHeight = document.documentElement.scrollHeight - document.documentElement.clientHeight;
        const scrolled = (window.scrollY / windowHeight) * 100;
        progressBar.style.width = `${scrolled}%`;
        ticking = false;
      });
      ticking = true;
    }
  });
}

// ============================================
// BACK TO TOP
// ============================================

function initBackToTop() {
  const backToTop = document.getElementById('back-to-top');
  if (!backToTop) return;

  let ticking = false;
  let isVisible = false;

  window.addEventListener('scroll', () => {
    if (!ticking) {
      window.requestAnimationFrame(() => {
        const shouldShow = window.scrollY > 400;
        if (shouldShow !== isVisible) {
          isVisible = shouldShow;
          if (shouldShow) {
            backToTop.classList.add('visible');
          } else {
            backToTop.classList.remove('visible');
          }
        }
        ticking = false;
      });
      ticking = true;
    }
  });

  backToTop.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  });
}

// ============================================
// AUTO-SCROLLER UTILITY
// ============================================

// Slowly scrolls an element right on loop, pausing when the user interacts.
// Returns a { stop } handle. Speed is px per animation frame (~60fps).
// loop:true duplicates children so the scroll wraps seamlessly.
function createAutoScroller(el, { speed = 0.5, pauseMs = 3000, startDelayMs = 1500, loop = false } = {}) {
  if (!el) return null;
  let rafId = null;
  let userPaused = false;
  let resumeTimer = null;

  if (loop) {
    Array.from(el.children).forEach(child => el.appendChild(child.cloneNode(true)));
  }

  function getMax() {
    return el.scrollWidth - el.clientWidth;
  }

  function step() {
    if (userPaused) return;

    if (loop) {
      const half = el.scrollWidth / 2;
      el.scrollLeft += speed;
      if (el.scrollLeft >= half) el.scrollLeft -= half;
    } else {
      const max = getMax();
      if (max <= 0) return;
      const next = el.scrollLeft + speed;
      el.scrollLeft = next >= max ? 0 : next;
    }

    rafId = requestAnimationFrame(step);
  }

  function pauseByUser() {
    if (userPaused) return;
    userPaused = true;
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    clearTimeout(resumeTimer);
    resumeTimer = setTimeout(() => {
      userPaused = false;
      rafId = requestAnimationFrame(step);
    }, pauseMs);
  }

  function stop() {
    userPaused = true;
    if (rafId) { cancelAnimationFrame(rafId); rafId = null; }
    clearTimeout(resumeTimer);
  }

  // Only listen to genuine user intent events (not 'scroll' which also fires on our writes)
  el.addEventListener('touchstart', pauseByUser, { passive: true });
  el.addEventListener('mousedown', pauseByUser);
  el.addEventListener('wheel', pauseByUser, { passive: true });
  el.addEventListener('keydown', pauseByUser);

  // Start after delay (let page settle first)
  const startTimer = setTimeout(() => {
    if (loop || getMax() > 0) rafId = requestAnimationFrame(step);
  }, startDelayMs);

  return { stop, pause: pauseByUser, _startTimer: startTimer };
}

// ============================================
// DYNAMIC CONTENT POPULATION
// ============================================

function populateDynamicContent() {
  populateTechStack();
  populateTimeline();
  populateProjects();
  populateSkills();
  populateLanguages();
  populateHobbies();
}

// Custom SVG Logos
const customSVGLogos = {
  'gRPC': `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 96 96" height="48" width="48"><path fill="#244b5a" d="M11.4052 61.9509c.6979.9285 1.6048 1.6794 2.6473 2.1918 1.1274.5584 2.3714.8408 3.6294.8238 1.0172.0266 2.0297-.1461 2.9805-.5084.7605-.2988 1.4394-.7734 1.9811-1.385.5084-.5959.8795-1.2963 1.0871-2.0515.2264-.8163.3384-1.66.333-2.507v-2.9454h-.0699c-.6593 1.045-1.6103 1.8739-2.7355 2.3844-1.0728.4671-2.2311.7059-3.4012.7013-1.1465.0086-2.2838-.2057-3.3485-.6311-1.0082-.4003-1.9306-.9894-2.7177-1.7358-.781-.7499-1.4014-1.6507-1.8235-2.6478-.44911-1.0526-.67592-2.1866-.6662-3.331-.00969-1.1411.20483-2.2729.63137-3.3313.40313-1.0013.99203-1.9174 1.73553-2.6999.7434-.7761 1.6387-1.3909 2.63-1.806 1.0608-.441 2.2001-.6617 3.3488-.6486.5231.003 1.045.0499 1.5602.14.5666.099 1.1197.2638 1.6481.4911 1.2545.5437 2.3389 1.4161 3.1386 2.525h.0699v-2.7354h2.3146v16.2705c-.0079.956-.1197 1.9083-.3333 2.8402-.2234 1.0076-.6664 1.9534-1.2973 2.7701-.7179.901-1.6366 1.6216-2.6826 2.1043-1.1457.5608-2.6419.8411-4.4886.8411-1.5001.0256-2.9902-.2485-4.383-.8063-1.3326-.5708-2.5279-1.4196-3.50622-2.4894l1.71802-1.8237Zm.4207-11.7116c-.0058.8357.1552 1.6641.4735 2.4368.3035.7415.7435 1.4195 1.2971 1.9986.5504.5741 1.2049 1.0382 1.9287 1.3678.754.3426 1.5738.5162 2.402.5083 1.6401.0059 3.2206-.6149 4.4182-1.7355.5881-.555 1.0488-1.2311 1.3502-1.9816.3247-.825.4741-1.7086.4384-2.5944.0059-.831-.1366-1.6564-.4209-2.4373-.2701-.7422-.6876-1.4221-1.2274-1.9987-.5548-.5845-1.223-1.0498-1.9636-1.3675-.82-.3485-1.7039-.5218-2.5949-.5086-.8282-.0076-1.648.166-2.402.5086-.7236.3299-1.378.7939-1.9287 1.3675-.5535.5794-.9935 1.2573-1.2974 1.9987-.3181.7729-.479 1.6014-.4732 2.4373Zm23.9844 8.4156h-2.5245V33.8282H40.93c2.5247 0 4.5175.5493 5.9786 1.6481 1.4608 1.099 2.1914 2.7588 2.1917 4.9793.0445 1.6118-.5403 3.1776-1.6305 4.3656-1.0872 1.1807-2.6593 1.8645-4.7163 2.0512l7.1534 11.7825h-3.086l-6.8024-11.5367h-4.208l-.0002 11.5367Zm0-13.851h4.4886c.9644.0203 1.9268-.0978 2.8577-.3508.6809-.182 1.3186-.4978 1.8761-.929.4497-.3619.7997-.8326 1.0167-1.3675.2134-.5415.3205-1.119.3157-1.701.0026-.5702-.1046-1.1356-.3157-1.6654-.2196-.5384-.5688-1.0143-1.0167-1.3852-.5521-.4398-1.1917-.7566-1.8761-.9293-.933-.2402-1.8945-.3522-2.8577-.333h-4.4886v8.6612Zm18.4441-10.9757h7.2238c2.5245 0 4.5173.5494 5.9783 1.6483 1.4608 1.0991 2.1914 2.7589 2.1918 4.9794 0 2.2212-.7306 3.8867-2.1918 4.9967-1.461 1.1106-3.4538 1.6658-5.9783 1.6656h-4.6988v11.5367h-2.525V33.8282Zm2.5252 10.9759h4.0677c.9644.0203 1.9268-.0978 2.8577-.3507.6808-.1821 1.3186-.498 1.8761-.9291.4497-.3619.7996-.8326 1.0167-1.3675.2135-.5414.3206-1.1189.3157-1.7009.0027-.5703-.1045-1.1357-.3157-1.6654-.2196-.5385-.5688-1.0143-1.0167-1.3853-.5521-.4396-1.1917-.7565-1.8761-.9293-.933-.2401-1.8945-.3522-2.8577-.3329h-4.0679l.0002 8.6611ZM95 54.7276c-.4443.6582-.9682 1.2589-1.56 1.7884-.6406.5755-1.3539 1.0647-2.1216 1.4549-.8196.4185-1.6842.7421-2.5771.9646-.9579.2378-1.9415.3555-2.9284.3505-1.7604.0165-3.5065-.3172-5.1368-.9816-3.1091-1.2564-5.5719-3.7256-6.8204-6.8379-.6681-1.66-1.0017-3.4357-.9816-5.225-.02-1.7892.3136-3.5649.9816-5.2249 1.2484-3.1122 3.7113-5.5813 6.8204-6.8374 1.6302-.6646 3.3764-.9984 5.1368-.9819 1.5867.0085 3.1574.3178 4.6288.9115 1.5694.628 2.9388 1.6704 3.9622 3.0158l-2.2088 1.6481c-.2968-.442-.6506-.843-1.0523-1.1923-.464-.4109-.976-.764-1.5249-1.0518-.5864-.3089-1.2035-.5557-1.8412-.7364-.6383-.1847-1.2994-.2791-1.9638-.2806-1.4729-.0242-2.9332.2751-4.2779.8766-1.2199.5535-2.3122 1.3533-3.2083 2.3492-.8868.9987-1.5716 2.1599-2.0166 3.4192-.9349 2.6431-.9349 5.5268 0 8.1699.4449 1.2593 1.1297 2.4204 2.0166 3.4189.8958.9962 1.9882 1.7962 3.2083 2.3494 1.3446.602 2.8049.9014 4.2779.8769.6527.0003 1.3041-.0584 1.9462-.1753.6533-.1202 1.2893-.3204 1.8937-.5961.637-.2922 1.2277-.6763 1.7533-1.14.5904-.5274 1.1038-1.1352 1.5251-1.8054L95 54.7276Z"/><path fill="url(#a)" d="m7.53809 41.9566-6.53851-6.49 6.49007-6.5386 6.53855 6.4901-6.49011 6.5385Z"/><path fill="url(#b)" d="m25.3301 39.1863-3.8352-3.8067 3.8068-3.8352 3.8351 3.8068-3.8067 3.8351Z"/><path fill="#244b5a" d="M7.77596 31.5034 3.8457 35.4631l3.95949 3.9303 3.34981-.0125-3.51277-3.4845 17.34547-.0643-1.5202 1.5305 1.6749-.0061 1.9653-1.9799-1.9799-1.965-1.6749.0061 1.5317 1.5195-17.34553.0643 3.48643-3.5105-3.34954.0124Z"/><defs><linearGradient id="a" x1="-646.313" x2="656.545" y1="-607.051" y2="-611.894" gradientUnits="userSpaceOnUse"><stop stop-color="#72c9c9"/><stop offset="1" stop-color="#02b0ad"/></linearGradient><linearGradient id="b" x1="-358.188" x2="406.007" y1="-341.49" y2="-344.331" gradientUnits="userSpaceOnUse"><stop stop-color="#03b6b4"/><stop offset="1" stop-color="#74cbca"/></linearGradient></defs></svg>`,
  'AWS RDS': `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" height="48" width="48"><path fill="#252f3e" d="M6.872425 10.077275c0 0.289175 0.03125 0.52365 0.085975 0.6956 0.062525 0.17195 0.140675 0.359525 0.2501 0.56275 0.039075 0.062525 0.0547 0.12505 0.0547 0.17975 0 0.078175 -0.046875 0.156325 -0.1485 0.234475l-0.4924 0.328275c-0.070325 0.0469 -0.140675 0.07035 -0.2032 0.07035 -0.07815 0 -0.156325 -0.0391 -0.234475 -0.109425 -0.109425 -0.11725 -0.203225 -0.2423 -0.281375 -0.36735 -0.07815 -0.132875 -0.156325 -0.281375 -0.2423 -0.46115 -0.609625 0.719075 -1.375575 1.0786 -2.29785 1.0786 -0.656525 0 -1.1801925 -0.187575 -1.56317 -0.56275 -0.382975 -0.37515 -0.5783725 -0.875375 -0.5783725 -1.500625 0 -0.66435 0.234475 -1.20365 0.7112425 -1.610075 0.4767675 -0.406425 1.10985 -0.60965 1.914875 -0.60965 0.26575 0 0.5393 0.02345 0.8285 0.06255 0.289175 0.039075 0.586175 0.1016 0.898825 0.17195v-0.570575c0 -0.594 -0.125075 -1.00825 -0.36735 -1.250525 -0.250125 -0.2423 -0.672175 -0.359525 -1.274 -0.359525 -0.27355 0 -0.554925 0.03125 -0.8441 0.1016 -0.2892 0.07035 -0.57055 0.156325 -0.844115 0.265725 -0.125055 0.054725 -0.218845 0.085975 -0.273555 0.101625 -0.0547125 0.015625 -0.09379 0.02345 -0.125055 0.02345 -0.10942 0 -0.1641325 -0.078175 -0.1641325 -0.2423v-0.382975c0 -0.12505 0.0156325 -0.21885 0.0547125 -0.27355 0.0390775 -0.054725 0.10942 -0.109425 0.2188425 -0.16415 0.273555 -0.140675 0.6018275 -0.257925 0.9848025 -0.3517 0.382975 -0.1016 0.7894 -0.1485 1.219275 -0.1485 0.930075 0 1.61005 0.211025 2.04775 0.633075 0.429875 0.42205 0.648725 1.06295 0.648725 1.9227v2.53235h0.015625Zm-3.17325 1.188c0.257925 0 0.523675 -0.0469 0.80505 -0.1407 0.28135 -0.093775 0.531475 -0.265725 0.7425 -0.5002 0.12505 -0.1485 0.21885 -0.312625 0.265725 -0.500225 0.0469 -0.187575 0.078175 -0.414225 0.078175 -0.679975v-0.32825c-0.226675 -0.054725 -0.46895 -0.101625 -0.719075 -0.132875 -0.2501 -0.031275 -0.4924 -0.0469 -0.734675 -0.0469 -0.523675 0 -0.90665 0.1016 -1.164575 0.312625 -0.257925 0.211025 -0.382975 0.50805 -0.382975 0.898825 0 0.36735 0.0938 0.6409 0.2892 0.828475 0.187575 0.1954 0.461125 0.2892 0.82065 0.2892Zm6.27615 0.8441c-0.1407 0 -0.2345 -0.02345 -0.297025 -0.07815 -0.062525 -0.0469 -0.117225 -0.156325 -0.164125 -0.304825L7.67745 5.68475c-0.0469 -0.156325 -0.07035 -0.257925 -0.07035 -0.312625 0 -0.12505 0.062525 -0.1954 0.1876 -0.1954h0.76595c0.1485 0 0.2501 0.02345 0.3048 0.07815 0.06255 0.0469 0.109425 0.156325 0.156325 0.304825l1.313075 5.1741 1.219275 -5.1741c0.039075 -0.156325 0.085975 -0.257925 0.1485 -0.304825s0.17195 -0.07815 0.312625 -0.07815h0.625275c0.1485 0 0.2501 0.02345 0.312625 0.07815 0.062525 0.0469 0.11725 0.156325 0.1485 0.304825l1.2349 5.236625 1.35215 -5.236625c0.0469 -0.156325 0.1016 -0.257925 0.156325 -0.304825 0.062525 -0.0469 0.164125 -0.07815 0.3048 -0.07815h0.726875c0.125075 0 0.1954 0.062525 0.1954 0.1954 0 0.039075 -0.0078 0.07815 -0.015625 0.12505s-0.02345 0.109425 -0.0547 0.1954l-1.883625 6.04165c-0.0469 0.156325 -0.1016 0.257925 -0.16415 0.304825 -0.062525 0.046875 -0.164125 0.07815 -0.297 0.07815h-0.67215c-0.1485 0 -0.2501 -0.02345 -0.31265 -0.07815 -0.062525 -0.054725 -0.117225 -0.156325 -0.1485 -0.31265L12.31225 6.685175l-1.20365 5.033425c-0.039075 0.1563 -0.085975 0.257925 -0.1485 0.312625 -0.062525 0.0547 -0.17195 0.07815 -0.312625 0.07815h-0.67215Zm10.04335 0.21105c-0.406425 0 -0.81285 -0.0469 -1.203625 -0.1407 -0.3908 -0.0938 -0.695625 -0.1954 -0.898825 -0.312625 -0.12505 -0.07035 -0.211025 -0.1485 -0.2423 -0.21885 -0.03125 -0.07035 -0.0469 -0.1485 -0.0469 -0.21885v-0.3986c0 -0.164125 0.062525 -0.2423 0.179775 -0.2423 0.0469 0 0.0938 0.007825 0.140675 0.02345 0.0469 0.015625 0.11725 0.0469 0.1954 0.07815 0.26575 0.11725 0.554925 0.21105 0.85975 0.273575 0.312625 0.062525 0.61745 0.093775 0.930075 0.093775 0.4924 0 0.875375 -0.085975 1.141125 -0.257925 0.26575 -0.17195 0.406425 -0.42205 0.406425 -0.7425 0 -0.21885 -0.07035 -0.3986 -0.211025 -0.5471 -0.1407 -0.1485 -0.406425 -0.281375 -0.7894 -0.406425l-1.1333 -0.351725c-0.57055 -0.17975 -0.992625 -0.4455 -1.25055 -0.7972 -0.257925 -0.3439 -0.390775 -0.726875 -0.390775 -1.1333 0 -0.328275 0.070325 -0.617475 0.211025 -0.867575 0.140675 -0.2501 0.32825 -0.46895 0.562725 -0.6409 0.234475 -0.17975 0.500225 -0.312625 0.81285 -0.406425 0.31265 -0.093775 0.6409 -0.132875 0.9848 -0.132875 0.17195 0 0.351725 0.007825 0.523675 0.031275 0.17975 0.02345 0.3439 0.0547 0.508025 0.085975 0.156325 0.039075 0.304825 0.07815 0.4455 0.12505 0.1407 0.0469 0.2501 0.0938 0.328275 0.1407 0.109425 0.062525 0.187575 0.12505 0.234475 0.195375 0.0469 0.062525 0.07035 0.1485 0.07035 0.257925v0.36735c0 0.164125 -0.06255 0.2501 -0.179775 0.2501 -0.062525 0 -0.164125 -0.03125 -0.297 -0.093775 -0.4455 -0.203225 -0.945725 -0.304825 -1.50065 -0.304825 -0.4455 0 -0.797225 0.07035 -1.0395 0.21885 -0.2423 0.1485 -0.36735 0.37515 -0.36735 0.6956 0 0.21885 0.07815 0.406425 0.234475 0.554925 0.156325 0.1485 0.4455 0.297 0.85975 0.429875l1.10985 0.351725c0.562725 0.17975 0.96915 0.429875 1.21145 0.750325 0.2423 0.32045 0.359525 0.687775 0.359525 1.0942 0 0.3361 -0.070325 0.6409 -0.2032 0.90665 -0.1407 0.265725 -0.328275 0.5002 -0.570575 0.6878 -0.242275 0.1954 -0.531475 0.336075 -0.86755 0.437675 -0.3517 0.109425 -0.71905 0.16415 -1.117675 0.16415Z" stroke-width="0.25"/><path fill="#FF9900" d="M21.496 16.118825c-2.571425 1.89925 -6.3074 2.9075 -9.519725 2.9075 -4.501925 0 -8.55835 -1.6648 -11.6221675 -4.4316 -0.2422905 -0.21885 -0.0234475 -0.51585 0.26574 -0.3439C3.933775 16.173525 8.02145 17.3381 12.24985 17.3381c2.852775 0 5.986925 -0.594025 8.870975 -1.8133 0.429875 -0.195375 0.797225 0.281375 0.375175 0.594025Zm1.070775 -1.219275c-0.328275 -0.422075 -2.172825 -0.203225 -3.009125 -0.101625 -0.2501 0.031275 -0.289175 -0.187575 -0.062525 -0.3517 1.4694 -1.0317 3.8845 -0.7347 4.16585 -0.3908 0.281375 0.351725 -0.07815 2.766825 -1.45375 3.923575 -0.211025 0.17975 -0.414225 0.085975 -0.32045 -0.148525 0.31265 -0.77375 1.00825 -2.5167 0.68 -2.930925Z" stroke-width="0.25"/></svg>`,
  'Tableau': `<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" height="48" width="48"><path fill="#7099a6" d="M11.626475 1.553125v1.068575h-1.911275v0.695h1.911275v2.128475h0.74715v-2.128475h1.95905v-0.695h-1.95905V0.4888925h-0.74715V1.553125Z" stroke-width="0.25"/><path fill="#eb912c" d="M5.380025 4.263625v1.55075H2.48706v0.973H5.380025v3.149275h1.072925V6.787375h2.936425v-0.973H6.45295V2.7129h-1.072925v1.550725Z" stroke-width="0.25"/><path fill="#59879b" d="M17.50345 4.263625v1.55075H14.610475v1.0208h2.892975v3.101475h1.11635V6.835175h2.892975v-1.0208H18.6198V2.7129h-1.11635v1.550725Z" stroke-width="0.25"/><path fill="#e8762c" d="M11.348275 9.54575v1.737525h-3.21875v1.29445h3.21875v3.47505h1.30315V12.577725h3.21875v-1.29445h-3.21875V7.808225h-1.30315v1.737525Z" stroke-width="0.25"/><path fill="#5b6591" d="M20.813675 10.4231v1.0903h-1.95905v0.8818h1.95905v2.17625h0.97735v-2.17625h1.95905v-0.8818h-1.95905v-2.17625h-0.97735v1.08595Z" stroke-width="0.25"/><path fill="#7099a6" d="M2.161275 10.518825v1.042525H0.25v0.73845h1.911275v2.085025h0.747125v-2.085025l1.959075 -0.0695v-0.66895h-1.959075v-2.085025H2.161275v1.0425Z" stroke-width="0.25"/><path fill="#c72035" d="M5.380025 15.4272v1.55075H2.48706v1.020775H5.380025v3.1015h1.116375v-3.1015h2.892975v-1.020775H6.4964V13.876475h-1.116375v1.550725Z" stroke-width="0.25"/><path fill="#1f447e" d="M17.50345 15.4272v1.55075H14.610475v0.973h2.892975v3.149275h1.11635V17.95095h2.892975v-0.973H18.6198V13.876475h-1.11635v1.550725Z" stroke-width="0.25"/><path fill="#5b6591" d="M11.5351 19.3669v1.08595h-1.95905v0.8818h1.95905v2.17625h0.977375v-2.17625h1.95905v-0.8818h-1.95905v-2.17625h-0.977375v1.0903Z" stroke-width="0.25"/></svg>`,
  'Google Antigravity': `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48" height="48" width="48"><defs><linearGradient id="antigravity-gradient" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" style="stop-color:#4285F4;stop-opacity:1" /><stop offset="25%" style="stop-color:#EA4335;stop-opacity:1" /><stop offset="50%" style="stop-color:#FBBC04;stop-opacity:1" /><stop offset="75%" style="stop-color:#34A853;stop-opacity:1" /><stop offset="100%" style="stop-color:#4285F4;stop-opacity:1" /></linearGradient></defs><circle cx="24" cy="24" r="20" fill="url(#antigravity-gradient)" opacity="0.9"/><path d="M24 8 L20 16 L28 16 Z" fill="white" opacity="0.95"/><path d="M24 40 L20 32 L28 32 Z" fill="white" opacity="0.95"/><circle cx="24" cy="24" r="6" fill="white" opacity="0.8"/><path d="M18 24 L24 18 L30 24 L24 30 Z" fill="#4285F4" opacity="0.7"/></svg>`
};

// Tech Stack Logo Mapping
const techLogos = {
  'HTML5': 'html5',
  'CSS3': 'css',
  'JavaScript': 'javascript',
  'React': 'react',
  'Responsive Design': 'responsive',
  'UI/UX Design': 'figma',
  'Web Animations': 'greensock',
  'Python': 'python',
  'Node.js': 'nodedotjs',
  'Express.js': 'express',
  'Flask (Backend)': 'flask',
  'MongoDB': 'mongodb',
  'MySQL': 'mysql',
  'AWS RDS': 'amazonaws',
  'C Programming': 'c',
  'Kotlin': 'kotlin',
  'Swift': 'swift',
  'LLM Prompt Engineering': ['openai', 'google', 'perplexity', 'x', 'github'],
  'AI-Assisted Development': ['openai', 'google', 'perplexity', 'x', 'github'],
  'Cloud Services': 'amazonaws',
  'Data Analysis & Visualization': 'tableau',
  'Git': 'git',
  'GitHub': 'github',
  'Docker': 'docker',
  'Firebase': 'firebase',
  'Cursor IDE': 'cursor',
  'VS Code': 'visualstudiocode',
  'Replit': 'replit',
  'Framer': 'framer',
  'Notion': 'notion',
  'Linux Basics': 'linux',
  'Microsoft Office': 'microsoft',
  'Google Antigravity': 'googleantigravity',
  'Interior Design': 'sketchup',
  'SketchUp / 5D Planner': 'sketchup',
  'Modern Farming': 'agro',
  'Canva Pro': 'canva',
  'AutoCAD': 'autocad',
  'PicsArt': 'picsart',
  'DaVinci Resolve': 'davinciresolve'
};

// Tech Stack
function populateTechStack() {
  const techList = document.getElementById('tech-list');
  if (!techList) return;

  // Clear existing content to prevent duplication
  techList.innerHTML = '';

  const technologies = [
    // Front End
    'HTML5', 'CSS3', 'JavaScript', 'React',
    'Responsive Design', 'UI/UX Design', 'Web Animations',
    // Back End
    'Python', 'Node.js', 'Express.js', 'Flask (Backend)',
    'MongoDB', 'MySQL', 'AWS RDS', 'gRPC', 'C Programming',
    // Android / iOS
    'Kotlin', 'Swift',
    // AI & Cloud
    'LLM Prompt Engineering', 'AI-Assisted Development',
    'Cloud Services', 'Data Analysis & Visualization',
    // Tools
    'Git', 'GitHub', 'Docker', 'Firebase', 'Tableau',
    'Cursor IDE', 'VS Code', 'Replit', 'Framer',
    'Notion', 'Linux Basics', 'Microsoft Office', 'Google Antigravity',
    // Other Domains
    'Interior Design', 'SketchUp / 5D Planner',
    'Modern Farming', 'Canva Pro', 'AutoCAD',
    'PicsArt', 'DaVinci Resolve'
  ];

  technologies.forEach((tech, index) => {
    const techItem = document.createElement('div');
    techItem.className = 'tech-item';
    techItem.textContent = tech;
    techItem.style.transitionDelay = `${index * 50}ms`;

    // Add logo on hover if available
    const logoName = techLogos[tech];
    const customSVG = customSVGLogos[tech];

    if (logoName || customSVG) {
      techItem.setAttribute('data-tech', tech);

      // Create logo tooltip
      const logoTooltip = document.createElement('div');
      logoTooltip.className = 'tech-logo-tooltip';

      // Check if it's a custom SVG logo (check this first)
      if (customSVG) {
        logoTooltip.innerHTML = customSVG;
        // Style the SVG
        const svg = logoTooltip.querySelector('svg');
        if (svg) {
          svg.style.width = '48px';
          svg.style.height = '48px';
          svg.style.display = 'block';
        }
        techItem.appendChild(logoTooltip);
        techList.appendChild(techItem);
        setTimeout(() => {
          techItem.classList.add('visible');
        }, 100 + index * 50);
        return; // Skip the rest of the loop for custom SVG
      }
      // Check if it's an array of logos (multiple logos)
      else if (Array.isArray(logoName)) {
        logoTooltip.classList.add('tech-logo-tooltip-multiple');
        logoName.forEach((logo, index) => {
          const logoImg = document.createElement('img');
          logoImg.src = `https://cdn.simpleicons.org/${logo}/3b82f6`;
          logoImg.alt = `${tech} logo ${index + 1}`;
          logoImg.loading = 'lazy';
          logoImg.onerror = function () {
            // If logo fails to load, try without color
            this.src = `https://cdn.simpleicons.org/${logo}`;
            this.onerror = function () {
              // If still fails, hide this specific logo
              this.style.display = 'none';
            };
          };
          logoTooltip.appendChild(logoImg);
        });
      } else {
        // Single logo
        techItem.setAttribute('data-logo', logoName);
        const logoImg = document.createElement('img');

        // For Cloud Services (AWS), try multiple formats
        if (logoName === 'amazonaws' && tech === 'Cloud Services') {
          // Try AWS logo with default color (orange)
          logoImg.src = `https://cdn.simpleicons.org/amazonaws`;
          logoImg.onerror = function () {
            // Try with orange color explicitly
            this.src = `https://cdn.simpleicons.org/amazonaws/FF9900`;
            this.onerror = function () {
              // Try with white color
              this.src = `https://cdn.simpleicons.org/amazonaws/ffffff`;
              this.onerror = function () {
                // If all fail, hide the tooltip
                logoTooltip.style.display = 'none';
              };
            };
          };
        } else {
          // Use jsdelivr CDN which is more reliable for SVG icons
          // Try icon name first, then fallbacks
          const iconFallbacks = {
            'canva': ['canva'],
            'microsoft': ['microsoft', 'microsoft365', 'microsoftoffice'],
            'visualstudiocode': ['visualstudiocode'],
            'cursor': ['cursor', 'visualstudiocode']
          };

          const fallbacks = iconFallbacks[logoName] || [logoName];
          let currentIndex = 0;

          const tryNextIcon = () => {
            if (currentIndex < fallbacks.length) {
              const currentIcon = fallbacks[currentIndex];
              // Use jsdelivr CDN for SVG icons (more reliable)
              logoImg.src = `https://cdn.jsdelivr.net/npm/simple-icons@v11/icons/${currentIcon}.svg`;

              logoImg.onerror = function () {
                currentIndex++;
                if (currentIndex < fallbacks.length) {
                  tryNextIcon();
                } else {
                  // If all fail, try cdn.simpleicons.org as last resort
                  logoImg.src = `https://cdn.simpleicons.org/${fallbacks[0]}`;
                  logoImg.onerror = function () {
                    // If all fail, hide the tooltip
                    logoTooltip.style.display = 'none';
                    if (logoTooltip.parentNode) {
                      logoTooltip.remove();
                    }
                  };
                }
              };
            }
          };

          // Start loading
          tryNextIcon();
        }
        logoImg.alt = `${tech} logo`;
        logoImg.loading = 'lazy';
        logoTooltip.appendChild(logoImg);
      }

      techItem.appendChild(logoTooltip);
    }

    techList.appendChild(techItem);

    // Animate in
    setTimeout(() => {
      techItem.classList.add('visible');
    }, 100 + index * 50);
  });
}

// Convert Western numerals to Arabic numerals
function toArabicNumerals(str) {
  if (!str || typeof str !== 'string') return str;

  const arabicDigits = ['٠', '١', '٢', '٣', '٤', '٥', '٦', '٧', '٨', '٩'];
  return str.replace(/\d/g, (digit) => arabicDigits[parseInt(digit)]);
}

// Timeline
// Stop any previously running timeline auto-play before re-rendering
// to prevent interval leaks when language is switched.
let _timelineStopFn = null;

function populateTimeline() {
  if (_timelineStopFn) { _timelineStopFn(); _timelineStopFn = null; }
  const track = document.getElementById('timeline');
  if (!track) return;

  // Clear existing
  track.innerHTML = '';

  const lang = currentLanguage || 'en';
  const t = translations[lang];
  if (!t || !t.education || !t.education.timeline) return;

  const timelineData = t.education.timeline;
  const isRTL = lang === 'ar';
  const processText = (text) => isRTL ? toArabicNumerals(text) : text;

  // Build slides
  timelineData.forEach((item) => {
    const slide = document.createElement('div');
    slide.className = 'timeline-item visible';

    const badge = processText(item.badge);
    const title = processText(item.title);
    const subtitle = processText(item.subtitle);
    const description = processText(item.description);

    let linksHTML = '';
    if (item.links) {
      const arrow = isRTL ? '↖' : '↗';
      const linksToDisplay = isRTL ? [...item.links].reverse() : item.links;
      linksHTML = `
        <div class="timeline-links">
          ${linksToDisplay.map(link => `
            <a href="${link.href}" target="_blank" rel="noopener noreferrer" class="timeline-link">
              ${processText(link.text)} ${arrow}
            </a>
          `).join('')}
        </div>
      `;
    }

    let milestonesHTML = '';
    if (item.milestones) {
      milestonesHTML = `
        <ul class="timeline-milestones">
          ${item.milestones.map(m => `<li>${processText(m)}</li>`).join('')}
        </ul>
      `;
    }

    slide.innerHTML = `
      <div class="timeline-content">
        <div class="timeline-header">
          <span class="timeline-badge">${badge}</span>
          <h3 class="timeline-title">${title}</h3>
        </div>
        <p class="timeline-subtitle">${subtitle}</p>
        <p class="timeline-description">${description}</p>
        ${milestonesHTML}
        ${linksHTML}
      </div>
    `;
    track.appendChild(slide);
  });

  // ── Carousel engine ──
  const total = timelineData.length;
  let current = 0;

  const counterEl = document.getElementById('edu-carousel-counter');
  const dotsContainer = document.getElementById('timeline-indicators');
  const prevBtn = document.getElementById('timeline-prev');
  const nextBtn = document.getElementById('timeline-next');

  // Build dot indicators
  if (dotsContainer) {
    dotsContainer.innerHTML = '';
    for (let i = 0; i < total; i++) {
      const dot = document.createElement('button');
      dot.className = 'edu-dot' + (i === 0 ? ' active' : '');
      dot.setAttribute('aria-label', `Go to milestone ${i + 1}`);
      dot.addEventListener('click', () => goTo(i));
      dotsContainer.appendChild(dot);
    }
  }

  // Set total in counter
  if (counterEl) {
    const totalSpan = counterEl.querySelector('.edu-counter-total');
    if (totalSpan) totalSpan.textContent = String(total).padStart(2, '0');
  }

  function goTo(index) {
    // Wrap infinitely in both directions
    current = ((index % total) + total) % total;

    // Slide the track — read actual slide width so mobile (88%) and desktop (84%) both work
    const slides = track.querySelectorAll('.timeline-item');
    const firstSlide = slides[0];
    let slideW = 84; // default desktop %
    if (firstSlide) {
      const basis = getComputedStyle(firstSlide).flexBasis;
      if (basis && basis.endsWith('%')) slideW = parseFloat(basis);
    }
    const offset = (100 - slideW) / 2; // center the first card
    track.style.transform = `translateX(calc(${offset}% - ${current * slideW}%))`;


    // Update counter
    if (counterEl) {
      const currentSpan = counterEl.querySelector('.edu-counter-current');
      if (currentSpan) currentSpan.textContent = String(current + 1).padStart(2, '0');
    }

    // Update dots
    if (dotsContainer) {
      dotsContainer.querySelectorAll('.edu-dot').forEach((dot, i) => {
        dot.classList.toggle('active', i === current);
      });
    }

    // Apply peek blur to adjacent slides (wrapping)
    const prevIdx = ((current - 1) % total + total) % total;
    const nextIdx = (current + 1) % total;
    slides.forEach((slide, i) => {
      slide.classList.remove('peek-prev', 'peek-next');
      if (i === prevIdx) slide.classList.add('peek-prev');
      if (i === nextIdx) slide.classList.add('peek-next');
    });
    // No button disabling — loop is infinite
  }

  // Init
  goTo(0);

  // Button handlers (clone to remove old listeners)
  if (prevBtn) {
    const newPrev = prevBtn.cloneNode(true);
    prevBtn.parentNode.replaceChild(newPrev, prevBtn);
    newPrev.addEventListener('click', () => goTo(current - 1));
  }
  if (nextBtn) {
    const newNext = nextBtn.cloneNode(true);
    nextBtn.parentNode.replaceChild(newNext, nextBtn);
    newNext.addEventListener('click', () => goTo(current + 1));
  }

  // Keyboard navigation when education section is visible
  const eduSection = document.getElementById('page-education');
  if (eduSection) {
    document.addEventListener('keydown', (e) => {
      // Only respond when education section is in view
      const rect = eduSection.getBoundingClientRect();
      const inView = rect.top < window.innerHeight && rect.bottom > 0;
      if (!inView) return;
      if (e.key === 'ArrowRight') goTo(current + 1);
      if (e.key === 'ArrowLeft') goTo(current - 1);
    });
  }

  // Touch/swipe support
  let touchStartX = 0;
  let touchEndX = 0;
  const viewport = track.parentElement;

  if (viewport) {
    viewport.addEventListener('touchstart', (e) => {
      touchStartX = e.changedTouches[0].screenX;
    }, { passive: true });

    viewport.addEventListener('touchend', (e) => {
      touchEndX = e.changedTouches[0].screenX;
      const diff = touchStartX - touchEndX;
      if (Math.abs(diff) > 50) {
        if (diff > 0) goTo(current + 1);  // swipe left → next
        else goTo(current - 1);            // swipe right → prev
      }
    }, { passive: true });
  }

  // ── Auto-play ──
  const AUTO_INTERVAL = 5000;   // advance every 5s
  const RESUME_DELAY  = 8000;   // resume 8s after last interaction
  let autoTimer = null;
  let resumeTimer = null;

  function autoAdvance() {
    goTo(current + 1); // goTo wraps infinitely
  }

  function startAuto() {
    stopAuto();
    autoTimer = setInterval(autoAdvance, AUTO_INTERVAL);
  }

  function stopAuto() {
    if (autoTimer) { clearInterval(autoTimer); autoTimer = null; }
    if (resumeTimer) { clearTimeout(resumeTimer); resumeTimer = null; }
  }

  function pauseAndResume() {
    stopAuto();
    resumeTimer = setTimeout(startAuto, RESUME_DELAY);
  }

  // Pause on any user interaction with the carousel
  const carouselEl = document.getElementById('edu-carousel');
  if (carouselEl) {
    carouselEl.addEventListener('mouseenter', () => stopAuto());
    carouselEl.addEventListener('mouseleave', () => {
      stopAuto();
      resumeTimer = setTimeout(startAuto, RESUME_DELAY);
    });
    // Pause on click (buttons, dots)
    carouselEl.addEventListener('click', pauseAndResume);
  }

  // Pause on keyboard interaction (already handled above, just reset timer)
  if (eduSection) {
    document.addEventListener('keydown', (e) => {
      if (!eduSection.classList.contains('active')) return;
      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') pauseAndResume();
    });
  }

  // Pause on touch
  if (viewport) {
    viewport.addEventListener('touchstart', pauseAndResume, { passive: true });
  }

  // Start auto-play and register stop handle for cleanup on re-render
  startAuto();
  _timelineStopFn = stopAuto;
}


// Projects
function populateProjects() {
  const projectsGrid = document.getElementById('projects-grid');
  if (!projectsGrid) return;

  // Clear existing projects to prevent duplication
  projectsGrid.innerHTML = '';

  const isRTL = currentLanguage === 'ar';

  const projects = [
    {
      badge: 'Featured',
      badgeAr: 'مميز',
      title: 'AshTech Software Solutions',
      titleAr: 'شركة آش تك للحلول البرمجية',
      meta: 'AI · Mobile · Web3 · Robotics · E-commerce',
      description: 'AshTech Software Solutions is a technology company built on one principle - great software changes everything. We specialize in varied domains including AI-powered systems, mobile applications, Web3/Blockchain ecosystems, robotics software, and comprehensive E-commerce platforms.',
      descriptionAr: 'شركة آش تك للحلول البرمجية هي شركة تكنولوجيا مبنية على مبدأ واحد - البرمجيات العظيمة تغير كل شيء. نحن متخصصون في مجالات متنوعة بما في ذلك الأنظمة المدعومة بالذكاء الاصطناعي، وتطبيقات الهاتف المحمول، ومنظومات Web3/Blockchain، وبرمجيات الروبوتات، ومنصات التجارة الإلكترونية الشاملة.',
      link: { text: 'Visit AshTech', textAr: 'زيارة آش تك', href: 'https://www.ashtechnologiesolutions.com/' },
      liveLink: { text: 'Live Demo', textAr: 'عرض مباشر', href: 'https://www.ashtechnologiesolutions.com/' },
      image: 'PP/projects/AshTech.png.png'
    },
    {
      badge: 'Featured',
      badgeAr: 'مميز',
      title: 'Basket Store — Premium MERN E-Commerce Platform',
      titleAr: 'منصة باسكت ستور للتجارة الإلكترونية',
      meta: 'MongoDB · Express · React · Node.js · Gemini API',
      description: 'A full-stack MERN (MongoDB, Express, React, Node.js) e-commerce app with dark-mode UI, seller/customer role switching, and Google Gemini–powered chat and product insights.',
      descriptionAr: 'تطبيق تجارة إلكترونية متكامل مبني بتقنية MERN (MongoDB, Express, React, Node.js) مع واجهة داكنة، وتبديل بين أدوار البائع والعميل، ودردشة ورؤى منتجات مدعومة بـ Google Gemini.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/E-Commerce-Backend-System-Entri-MERN-2-ME5' },
      liveLink: { text: 'Live Demo', textAr: 'عرض مباشر', href: 'https://e-commerce-backend-system-entri-mer-nu.vercel.app/' },
      image: 'PP/projects/basket-store.png.png'
    },
    {
      badge: 'Study Project',
      badgeAr: 'مشروع دراسي',
      title: 'Bill Scanning Based Reward Intelligence System',
      titleAr: 'نظام ذكاء المكافآت المعتمد على مسح الفواتير',
      meta: 'JS · React · GEMINI API',
      description: 'Developed a reward intelligence system based on bill scanning, integrating Gemini API for robust data extraction. Built as a Phase 3 study project showcasing full-stack capabilities.',
      descriptionAr: 'تم تطوير نظام ذكاء للمكافآت يعتمد على مسح الفواتير، مع دمج واجهة Gemini API لاستخراج بيانات قوية. تم بناؤه كمشروع دراسي للمرحلة الثالثة يعرض قدرات Full-Stack.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/Bill-Scanning-Based-Reward-Intelligence-System-study-project-bits-poc-phase-3-Team-ARAJ' },
      liveLink: { text: 'Live Demo', textAr: 'عرض مباشر', href: 'https://ashfaaqkt.github.io/Bill-Scanning-Based-Reward-Intelligence-System-study-project-bits-poc-phase-3-Team-ARAJ/public/index.html' },
      image: 'PP/projects/bill-scanning.png.png'
    },
    {
      badge: 'Study Project',
      badgeAr: 'مشروع دراسي',
      title: 'StudyBuddy Full-Stack Application',
      titleAr: 'تطبيق StudyBuddy المتكامل',
      meta: 'MERN · Gemini AI · JWT',
      description: 'A complete full-stack educational platform built as the final capstone for the Entri Elevate program. Features secure JWT authentication, AI-powered note summarization and quiz generation via Gemini API, a Pomodoro timer, and a responsive analytics dashboard.',
      descriptionAr: 'منصة تعليمية متكاملة بنيت كمشروع التخرج النهائي لبرنامج Entri Elevate. تشمل مصادقة JWT الآمنة، وتلخيص الملاحظات وإنشاء الاختبارات تلقائياً عبر واجهة Gemini، ومؤقت بومودورو، ولوحة معلومات تحليلية متجاوبة.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/StudyBuddy-Entri-Final-Project-By-Ashfaaq' },
      liveLink: { text: 'Live Demo', textAr: 'عرض مباشر', href: 'https://study-buddy-entri-final-project-by.vercel.app' },
      image: 'PP/projects/studybuddy.png.png'
    },
    {
      badge: 'Featured',
      badgeAr: 'مميز',
      title: 'Personal Portfolio Website',
      titleAr: 'موقع المحفظة الشخصي',
      meta: 'HTML · CSS · JavaScript',
      description: 'Designed and deployed ashfaaqkt.com with performance and clean UX top-of-mind. Built as a static site and hosted via GitHub, using a custom domain purchased from GoDaddy. Features modern animations, responsive design, and optimized loading.',
      descriptionAr: 'تم تصميم ونشر ashfaaqkt.com مع التركيز على الأداء وتجربة المستخدم النظيفة. تم بناؤه كموقع ثابت ومستضاف عبر GitHub مع ربط نطاق مخصص تم شراؤه من GoDaddy. يتميز بالرسوم المتحركة الحديثة والتصميم المتجاوب والتحميل المحسّن.',
      link: { text: 'Visit Website', textAr: 'زيارة الموقع', href: 'https://ashfaaqkt.com' },
      liveLink: { text: 'Live Demo', textAr: 'عرض مباشر', href: 'https://ashfaaqkt.com' },
      image: 'PP/projects/ashfaaq-portfolio.png.png'
    },
    {
      badge: 'FinTech',
      badgeAr: 'التكنولوجيا المالية',
      title: 'Banking gRPC System',
      titleAr: 'نظام Banking gRPC',
      meta: 'Python · SQL · gRPC',
      description: 'Secure transaction system with client/server architecture, authentication layers, and SQL-backed persistence. Implements robust error handling and transaction management for financial operations.',
      descriptionAr: 'نظام معاملات آمن مع بنية عميل/خادم وطبقات المصادقة والاستمرارية المدعومة بـ SQL. ينفذ معالجة أخطاء قوية وإدارة معاملات للعمليات المالية.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/Banking-gRPC-System' },
      image: 'PP/projects/Banking-gRPC-System.png.png'
    },
    {
      badge: 'Cloud',
      badgeAr: 'السحابة',
      title: 'Database & AWS RDS Integration',
      titleAr: 'تكامل قاعدة البيانات و AWS RDS',
      meta: 'SQL · AWS · Cloud',
      description: 'Deployed production-ready database schemas on AWS RDS, enabling scalable data storage with automated backups, monitoring, and high availability. Demonstrates cloud infrastructure expertise.',
      descriptionAr: 'تم نشر مخططات قاعدة بيانات جاهزة للإنتاج على AWS RDS، مما يتيح تخزين بيانات قابل للتوسع مع النسخ الاحتياطي التلقائي والمراقبة والتوفر العالي. يظهر خبرة في البنية التحتية السحابية.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/Database-AWS-RDS-Integration' },
      image: 'PP/projects/Database-AWS-RDS-Integration.png.png'
    },
    {
      badge: 'Data Analysis',
      badgeAr: 'تحليل البيانات',
      title: 'Tableau Mental Health Data Analysis',
      titleAr: 'تحليل بيانات الصحة العقلية في Tableau',
      meta: 'Tableau · Data Visualization',
      description: 'Interactive visualizations using charts, graphs, and trend analysis to uncover mental health patterns across different demographic groups. Transforms raw data into actionable insights.',
      descriptionAr: 'تصورات تفاعلية باستخدام الرسوم البيانية والرسوم والتحليل الاتجاهي للكشف عن أنماط الصحة العقلية عبر مجموعات ديموغرافية مختلفة. يحول البيانات الخام إلى رؤى قابلة للتنفيذ.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/Tableau-Mental-Health-Data-Analysis-Project' },
      image: 'PP/projects/Tableau-Mental-Health-Data-Analysis.png.png'
    },
    {
      badge: 'Data Viz',
      badgeAr: 'تصور البيانات',
      title: 'Airbnb Dashboards',
      titleAr: 'لوحات معلومات Airbnb',
      meta: 'Tableau · Business Intelligence',
      description: 'Visualized pricing, occupancy, and demand insights to support rental management decisions. Created comprehensive dashboards for market analysis and revenue optimization.',
      descriptionAr: 'تصور رؤى التسعير والإشغال والطلب لدعم قرارات إدارة الإيجار. إنشاء لوحات معلومات شاملة لتحليل السوق وتحسين الإيرادات.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/Airbnb-Dashboard-in-Tableau' },
      image: 'PP/projects/Airbnb-Dashboards.png.png'
    },
    {
      badge: 'Database',
      badgeAr: 'قاعدة البيانات',
      title: 'Education System Database',
      titleAr: 'قاعدة بيانات نظام التعليم',
      meta: 'SQL · Database Design',
      description: 'Complete SQL database system with schema design, data management, and complex queries supporting course assignments, enrollments, and student-instructor workflows. Demonstrates advanced SQL skills.',
      descriptionAr: 'نظام قاعدة بيانات SQL كامل مع تصميم المخطط وإدارة البيانات والاستعلامات المعقدة التي تدعم مهام الدورة والتسجيلات وسير عمل الطالب-المدرب. يظهر مهارات SQL متقدمة.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/Database-Creation-and-Data-Manipulation-for-an-Education-System' },
      image: 'PP/projects/Education-System-Database.png.png'
    },
    {
      badge: 'Data Analysis',
      badgeAr: 'تحليل البيانات',
      title: 'Football Player Data Analysis',
      titleAr: 'تحليل بيانات لاعبي كرة القدم',
      meta: 'Python · Pandas · Visualization',
      description: 'End-to-end data analysis workflow covering player demographics, performance metrics, and market valuation through data cleaning, EDA, and comprehensive visualizations. Showcases data science capabilities.',
      descriptionAr: 'سير عمل تحليل بيانات شامل يغطي التركيبة السكانية للاعبين ومقاييس الأداء وتقييم السوق من خلال تنظيف البيانات والتحليل الاستكشافي والتصورات الشاملة. يعرض قدرات علم البيانات.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/Football-Players-Data-Analysis-Project' },
      image: 'PP/projects/Football-Player-Data-Analysis.png.png'
    },
    {
      badge: 'DevOps',
      badgeAr: 'DevOps',
      title: 'DevOps Workflow Implementation',
      titleAr: 'تنفيذ سير عمل DevOps',
      meta: 'Git · GitHub · Docker · Flask',
      description: 'Complete DevOps workflow with Git version control, GitHub integration, and Docker containerization for Flask applications. Demonstrates end-to-end CI/CD practices and container orchestration.',
      descriptionAr: 'سير عمل DevOps كامل مع التحكم في الإصدارات Git وتكامل GitHub وحاويات Docker لتطبيقات Flask. يظهر ممارسات CI/CD الشاملة وتنسيق الحاويات.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/DevOps-Workflow-Implementation-using-Git-GitHub-Docker' },
      image: 'PP/projects/DevOps-Workflow.png.jpg'
    },
    {
      badge: 'Systems',
      badgeAr: 'الأنظمة',
      title: 'HTTP Client in C',
      titleAr: 'عميل HTTP في C',
      meta: 'C · Network Programming',
      description: 'Low-level HTTP client implementation using raw TCP sockets to connect to web servers, send requests, and receive responses. Demonstrates deep understanding of network protocols and systems programming.',
      descriptionAr: 'تنفيذ عميل HTTP منخفض المستوى باستخدام مقابس TCP الخام للاتصال بخوادم الويب وإرسال الطلبات واستقبال الردود. يظهر فهماً عميقاً لبروتوكولات الشبكة وبرمجة الأنظمة.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/Implementation-of-an-HTTP-Client-in-C-for-Server-Communication' },
      image: 'PP/projects/HTTP-Client-in-C.png.png'
    },
    {
      badge: 'UI/UX Design',
      badgeAr: 'تصميم واجهة المستخدم',
      title: 'ETTI App UI/UX Design',
      titleAr: 'تصميم واجهة مستخدم تطبيق ETTI',
      meta: 'MockUp (iPad) · UI/UX Design',
      description: 'A multi-service delivery and mobility app concept. ETTI, meaning "reached" in Malayalam, represents speed, trust, and reliability. The app combines food delivery, groceries, auto-rickshaw rides, porter services, and an AI assistant into one seamless platform. UI/UX mockups designed on iPad using MockUp showcase the complete visual flow.',
      descriptionAr: 'مفهوم تطبيق توصيل متعدد الخدمات والتنقل. ETTI، بمعنى "وصل" في المالايالامية، يمثل السرعة والثقة والموثوقية. يجمع التطبيق بين توصيل الطعام والبقالة وركوب الريكشا وخدمات الحمالين ومساعد ذكاء اصطناعي في منصة سلسة واحدة. النماذج الأولية لواجهة المستخدم/تجربة المستخدم المصممة على iPad باستخدام MockUp تعرض التدفق البصري الكامل.',
      link: { text: 'View on GitHub', textAr: 'عرض على GitHub', href: 'https://github.com/ashfaaqkt/ETTI-App-MockUp-design' },
      image: 'PP/projects/ETTI-App-UI-UX-Design.png'
    }
  ];

  // Setup Filters & Search State
  let currentFilter = 'all';
  let currentSearch = '';

  const projectsFilters = document.getElementById('projects-filters');
  const projectsSearchInput = document.getElementById('projects-search-input');

  const filterCategories = [{ id: 'all', label: 'All', labelAr: 'الكل' }];
  const uniqueBadges = new Set();
  
  projects.forEach(p => {
    if (!uniqueBadges.has(p.badge)) {
      uniqueBadges.add(p.badge);
      filterCategories.push({
        id: p.badge,
        label: p.badge,
        labelAr: p.badgeAr
      });
    }
  });

  if (projectsFilters) {
    projectsFilters.innerHTML = '';
    filterCategories.forEach((filter, index) => {
      const filterBtn = document.createElement('button');
      filterBtn.className = `project-filter-btn ${index === 0 ? 'active' : ''}`;
      filterBtn.textContent = isRTL && filter.labelAr ? filter.labelAr : filter.label;
      filterBtn.setAttribute('data-category', filter.id);
      
      filterBtn.addEventListener('click', () => {
        projectsFilters.querySelectorAll('.project-filter-btn').forEach(btn => btn.classList.remove('active'));
        filterBtn.classList.add('active');
        currentFilter = filter.id;
        renderProjects();
      });
      projectsFilters.appendChild(filterBtn);
    });
  }

  // Filter Scroll Buttons Logic
  const scrollLeftBtn = document.getElementById('filter-scroll-left');
  const scrollRightBtn = document.getElementById('filter-scroll-right');
  const projectsFiltersWrapper = document.getElementById('projects-filters-wrapper');

  if (projectsFilters && scrollLeftBtn && scrollRightBtn) {
    const scrollAmount = 200;

    const updateScrollButtons = () => {
      const maxScroll = projectsFilters.scrollWidth - projectsFilters.clientWidth;

      if (maxScroll <= 0) {
        scrollLeftBtn.classList.remove('active');
        scrollRightBtn.classList.remove('active');
        if (projectsFiltersWrapper) {
          projectsFiltersWrapper.classList.add('at-start', 'at-end');
        }
        return;
      }

      const scrollL = projectsFilters.scrollLeft;
      const isRTLDir = window.getComputedStyle(projectsFilters).direction === 'rtl';

      if (isRTLDir) {
        scrollRightBtn.classList.toggle('active', scrollL < 0);
        scrollLeftBtn.classList.toggle('active', Math.abs(scrollL) < maxScroll - 1);
      } else {
        scrollLeftBtn.classList.toggle('active', scrollL > 0);
        scrollRightBtn.classList.toggle('active', Math.ceil(scrollL) < maxScroll);
      }

      // Gradient fade visibility
      if (projectsFiltersWrapper) {
        projectsFiltersWrapper.classList.toggle('at-start', scrollL <= 1);
        projectsFiltersWrapper.classList.toggle('at-end', Math.ceil(scrollL) >= maxScroll - 1);
      }
    };

    scrollLeftBtn.addEventListener('click', () => {
      projectsFilters.scrollBy({ left: -scrollAmount, behavior: 'smooth' });
    });

    scrollRightBtn.addEventListener('click', () => {
      projectsFilters.scrollBy({ left: scrollAmount, behavior: 'smooth' });
    });

    projectsFilters.addEventListener('scroll', updateScrollButtons);
    window.addEventListener('resize', updateScrollButtons);

    // Initial check after categories populate
    setTimeout(updateScrollButtons, 100);
  }

  if (projectsSearchInput) {
    const placeholderText = isRTL ? projectsSearchInput.getAttribute('data-ar') : projectsSearchInput.getAttribute('data-en');
    if (placeholderText) projectsSearchInput.placeholder = placeholderText;

    projectsSearchInput.addEventListener('input', (e) => {
      currentSearch = e.target.value.toLowerCase();
      renderProjects();
    });
  }

  function renderProjects() {
    projectsGrid.innerHTML = '';
    
    // Filter projects
    const filteredProjects = projects.filter(p => {
      const matchesFilter = currentFilter === 'all' || p.badge === currentFilter;
      const searchTerms = [
        p.title, p.titleAr, p.description, p.descriptionAr, p.badge, p.badgeAr, p.meta
      ].join(' ').toLowerCase();
      const matchesSearch = searchTerms.includes(currentSearch);
      return matchesFilter && matchesSearch;
    });

    if (filteredProjects.length === 0) {
      const emptyMsg = isRTL ? 'لم يتم العثور على مشاريع...' : 'No projects found...';
      projectsGrid.innerHTML = `<p style="grid-column: 1/-1; text-align: center; color: var(--color-text-secondary); padding: 2rem;">${emptyMsg}</p>`;
      return;
    }

    filteredProjects.forEach((project, index) => {
      const projectCard = document.createElement('div');
      projectCard.className = 'project-card';
      projectCard.style.transitionDelay = `${index * 50}ms`;

      // In RTL (Arabic) mode: switch description to Arabic translation.
      const badge = project.badge;
      const title = project.title;
      const description = (isRTL && project.descriptionAr) ? project.descriptionAr : project.description;
      const linkText = (isRTL && project.link.textAr) ? project.link.textAr : project.link.text;


      // Image: always use static image; wrap in clickable link if project has a live demo
      const hasLive = !!project.liveLink;
      const liveUrl = hasLive ? project.liveLink.href : '';
      const imageTag = `<img src="${project.image}" alt="${title}" class="project-image" loading="lazy" onerror="this.style.display='none'; this.parentElement.classList.add('no-image');" />`;
      const imageHtml = hasLive
        ? `<a href="${liveUrl}" target="_blank" rel="noopener noreferrer" class="project-image-link" title="Open live demo">${imageTag}<span class="project-image-live-badge">● LIVE</span></a>`
        : imageTag;

      projectCard.innerHTML = `
        <div class="project-image-wrapper">
          ${imageHtml}
          <span class="project-badge">${badge}</span>
        </div>
        <div class="project-body">
          <h3 class="project-title">${title}</h3>
          <div class="project-tags">
            ${project.meta.split(' · ').map(tag => `<span class="project-tag">${tag}</span>`).join('')}
          </div>
          <p class="project-description">${description}</p>
          <div class="project-links-container">
            <a href="${project.link.href}" target="_blank" rel="noopener noreferrer" class="project-link">
              <span class="project-link-text">${linkText}</span>
              <svg class="project-link-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3"/>
              </svg>
              <svg class="project-link-github" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2z"/>
              </svg>
            </a>
          </div>
        </div>
      `;

      projectsGrid.appendChild(projectCard);

      requestAnimationFrame(() => {
        const rect = projectCard.getBoundingClientRect();
        const isInViewport = rect.top < window.innerHeight && rect.bottom > 0;

        if (isInViewport) {
          setTimeout(() => {
            projectCard.classList.add('visible');
            animatedElementsSet.add(projectCard);
          }, index * 50);
        } else {
          if (globalAnimationObserver && !animatedElementsSet.has(projectCard)) {
            globalAnimationObserver.observe(projectCard);
          }
          setTimeout(() => {
            if (!projectCard.classList.contains('visible')) {
              projectCard.classList.add('visible');
              animatedElementsSet.add(projectCard);
            }
          }, 500 + (index * 50));
        }
      });
    });

    setTimeout(() => {
      const projectCards = document.querySelectorAll('.project-card:not(.visible)');
      projectCards.forEach(card => {
        if (globalAnimationObserver && !animatedElementsSet.has(card)) {
          globalAnimationObserver.observe(card);
        }
      });
    }, 100);

    // ── Mobile carousel dot indicators ──
    setupProjectCarouselDots(filteredProjects.length);

    // ── Auto-scroll hint on mobile carousel ──
    if (window.matchMedia('(max-width: 768px)').matches) {
      if (window._projectsGridScroller) window._projectsGridScroller.stop();
      window._projectsGridScroller = createAutoScroller(projectsGrid, { speed: 0.35, pauseMs: 3000, startDelayMs: 2500 });
    }
  }

  function setupProjectCarouselDots(count) {
    const dotsContainer = document.getElementById('projects-carousel-dots');
    if (!dotsContainer) return;

    dotsContainer.innerHTML = '';

    // Only show dots if we're on small screen (carousel mode)
    const isMobile = window.matchMedia('(max-width: 530px)').matches;
    if (!isMobile || count <= 1) return;

    for (let i = 0; i < count; i++) {
      const dot = document.createElement('button');
      dot.className = 'p-dot' + (i === 0 ? ' active' : '');
      dot.setAttribute('aria-label', `Project ${i + 1}`);
      dot.addEventListener('click', () => {
        const cards = projectsGrid.querySelectorAll('.project-card');
        if (cards[i]) {
          const cardLeft = cards[i].getBoundingClientRect().left
            - projectsGrid.getBoundingClientRect().left
            + projectsGrid.scrollLeft;
          projectsGrid.scrollTo({ left: cardLeft, behavior: 'smooth' });
        }
      });
      dotsContainer.appendChild(dot);
    }

    // Track scroll to update active dot
    let scrollTimeout;
    projectsGrid.addEventListener('scroll', () => {
      clearTimeout(scrollTimeout);
      scrollTimeout = setTimeout(() => {
        const cards = projectsGrid.querySelectorAll('.project-card');
        const gridRect = projectsGrid.getBoundingClientRect();
        const gridCenter = gridRect.left + gridRect.width * 0.35;

        let closestIdx = 0;
        let closestDist = Infinity;

        cards.forEach((card, idx) => {
          const cardRect = card.getBoundingClientRect();
          const cardCenter = cardRect.left + cardRect.width / 2;
          const dist = Math.abs(cardCenter - gridCenter);
          if (dist < closestDist) {
            closestDist = dist;
            closestIdx = idx;
          }
        });

        dotsContainer.querySelectorAll('.p-dot').forEach((dot, i) => {
          dot.classList.toggle('active', i === closestIdx);
        });
      }, 50);
    }, { passive: true });
  }

  // Re-setup dots on resize
  window.addEventListener('resize', () => {
    const cardCount = projectsGrid.querySelectorAll('.project-card').length;
    setupProjectCarouselDots(cardCount);
  });

  // Initial render
  renderProjects();
}

// Skills
function populateSkills() {
  const skillsGrid = document.getElementById('skills-grid');
  const skillsFilters = document.getElementById('skills-filters');
  if (!skillsGrid || !skillsFilters) return;

  // Clear existing content to prevent duplication
  skillsGrid.innerHTML = '';
  skillsFilters.innerHTML = '';

  const isRTL = currentLanguage === 'ar';

  const skillsData = {
    all: [
      {
        category: 'frontend',
        title: 'Front End',
        titleAr: 'الواجهة الأمامية',
        skills: [
          'React',
          'HTML',
          'CSS',
          'JavaScript',
          'Responsive Design',
          'UI/UX Design',
          'Web Animations'
        ]
      },
      {
        category: 'uiux',
        title: 'UI/UX Design',
        titleAr: 'تصميم واجهة المستخدم',
        skills: [
          'Figma',
          'MockUp (iPad)',
          'Adobe XD'
        ]
      },
      {
        category: 'backend',
        title: 'Back End',
        titleAr: 'الخلفية',
        skills: [
          'Python',
          'Node.js',
          'Express.js',
          'Flask (Backend)',
          'MongoDB',
          'MySQL',
          'AWS RDS',
          'gRPC',
          'C Programming'
        ]
      },
      {
        category: 'mobile',
        title: 'Android / iOS Development',
        titleAr: 'تطوير Android / iOS',
        skills: [
          'Kotlin',
          'Swift',
          'Android Studio'
        ]
      },
      {
        category: 'ai',
        title: 'AI & Cloud',
        titleAr: 'الذكاء الاصطناعي والسحابة',
        skills: [
          'LLM Prompt Engineering',
          'AI-Assisted Development',
          'Cloud Services',
          'Data Analysis & Visualization'
        ]
      },
      {
        category: 'tools',
        title: 'Developer Tools',
        titleAr: 'أدوات المطور',
        skills: [
          'Git',
          'GitHub',
          'Docker',
          'Firebase',
          'Tableau',
          'Cursor IDE',
          'VS Code',
          'Replit',
          'Framer',
          'Notion',
          'Linux Basics',
          'Microsoft Office',
          'Google Antigravity'
        ]
      },
      {
        category: 'soft',
        title: 'Soft Skills',
        titleAr: 'المهارات الناعمة',
        skills: [
          'Problem-Solving',
          'Communication',
          'Adaptability',
          'Writing Skills',
          'Team Collaboration'
        ],
        skillsAr: [
          'حل المشكلات',
          'التواصل',
          'القدرة على التكيف',
          'مهارات الكتابة',
          'العمل الجماعي'
        ]
      },
      {
        category: 'others',
        title: 'Other Domains & Tools',
        titleAr: 'مجالات وأدوات أخرى',
        skills: [
          'Interior Design',
          'SketchUp / 5D Planner',
          'Modern Farming',
          'Canva Pro',
          'AutoCAD',
          'PicsArt',
          'DaVinci Resolve'
        ]
      }
    ]
  };

  // Create filters with Arabic translations
  const filterCategories = [
    { id: 'all', label: 'All', labelAr: 'الكل' },
    { id: 'frontend', label: 'Front End', labelAr: 'الواجهة الأمامية' },
    { id: 'uiux', label: 'UI/UX Design', labelAr: 'تصميم واجهة المستخدم' },
    { id: 'backend', label: 'Back End', labelAr: 'الخلفية' },
    { id: 'mobile', label: 'Android / iOS', labelAr: 'Android / iOS' },
    { id: 'ai', label: 'AI & Cloud', labelAr: 'الذكاء الاصطناعي والسحابة' },
    { id: 'tools', label: 'Tools', labelAr: 'الأدوات' },
    { id: 'soft', label: 'Soft Skills', labelAr: 'المهارات الناعمة' },
    { id: 'others', label: 'Others', labelAr: 'أخرى' }
  ];

  filterCategories.forEach((filter, index) => {
    const filterBtn = document.createElement('button');
    filterBtn.className = `skill-filter ${index === 0 ? 'active' : ''}`;
    const filterLabel = (isRTL && filter.labelAr) ? filter.labelAr : filter.label;
    filterBtn.textContent = filterLabel;
    filterBtn.setAttribute('data-category', filter.id);
    filterBtn.addEventListener('click', () => {
      // Update active filter
      skillsFilters.querySelectorAll('.skill-filter').forEach(btn => {
        btn.classList.remove('active');
      });
      filterBtn.classList.add('active');

      // Clear search when switching categories
      const si = document.getElementById('skills-search-input');
      if (si) {
        si.value = '';
        skillsGrid.querySelectorAll('.skill-card').forEach(c => c.classList.remove('search-hidden'));
      }

      // Filter skills
      skillsGrid.querySelectorAll('.skill-card').forEach(card => {
        if (filter.id === 'all' || card.getAttribute('data-category') === filter.id) {
          card.classList.remove('hidden');
          setTimeout(() => {
            card.classList.add('visible');
          }, 50);
        } else {
          card.classList.remove('visible');
          setTimeout(() => {
            card.classList.add('hidden');
          }, 300);
        }
      });
    });
    skillsFilters.appendChild(filterBtn);
  });

  // Skills Scroll Buttons Logic
  const scrollLeftBtn = document.getElementById('skills-scroll-left');
  const scrollRightBtn = document.getElementById('skills-scroll-right');
  const skillsFiltersWrapper = document.getElementById('skills-filters-wrapper');

  if (skillsFilters && scrollLeftBtn && scrollRightBtn) {
    const scrollAmount = 200;

    const updateScrollButtons = () => {
      const maxScroll = skillsFilters.scrollWidth - skillsFilters.clientWidth;

      if (maxScroll <= 0) {
        scrollLeftBtn.classList.remove('active');
        scrollRightBtn.classList.remove('active');
        if (skillsFiltersWrapper) {
          skillsFiltersWrapper.classList.add('at-start', 'at-end');
        }
        return;
      }

      const scrollL = skillsFilters.scrollLeft;
      const isRTLDir = window.getComputedStyle(skillsFilters).direction === 'rtl';

      if (isRTLDir) {
        scrollRightBtn.classList.toggle('active', scrollL < 0);
        scrollLeftBtn.classList.toggle('active', Math.abs(scrollL) < maxScroll - 1);
      } else {
        scrollLeftBtn.classList.toggle('active', scrollL > 0);
        scrollRightBtn.classList.toggle('active', Math.ceil(scrollL) < maxScroll);
      }

      // Gradient fade visibility
      if (skillsFiltersWrapper) {
        skillsFiltersWrapper.classList.toggle('at-start', scrollL <= 1);
        skillsFiltersWrapper.classList.toggle('at-end', Math.ceil(scrollL) >= maxScroll - 1);
      }
    };

    scrollLeftBtn.addEventListener('click', () => {
      skillsFilters.scrollBy({ left: -scrollAmount, behavior: 'smooth' });
    });

    scrollRightBtn.addEventListener('click', () => {
      skillsFilters.scrollBy({ left: scrollAmount, behavior: 'smooth' });
    });

    skillsFilters.addEventListener('scroll', updateScrollButtons);
    window.addEventListener('resize', updateScrollButtons);

    // Initial check after categories populate
    setTimeout(updateScrollButtons, 100);
  }

  // Search input
  const searchInput = document.getElementById('skills-search-input');
  if (searchInput) {
    searchInput.placeholder = isRTL ? 'ابحث عن المهارات...' : 'Search skills...';
    searchInput.addEventListener('input', () => {
      const query = searchInput.value.trim().toLowerCase();
      skillsGrid.querySelectorAll('.skill-card').forEach(card => {
        const title = card.querySelector('h3')?.textContent.toLowerCase() || '';
        const pills = Array.from(card.querySelectorAll('.skill-pill')).map(p => p.textContent.toLowerCase());
        const matches = !query || title.includes(query) || pills.some(p => p.includes(query));
        card.classList.toggle('search-hidden', !matches);
      });
    });
  }

  // Create skill cards
  skillsData.all.forEach((skillGroup, index) => {
    const skillCard = document.createElement('div');
    skillCard.className = 'skill-card';
    skillCard.setAttribute('data-category', skillGroup.category);
    skillCard.style.transitionDelay = `${index * 100}ms`;

    // Use Arabic translations if available and in RTL mode
    const title = (isRTL && skillGroup.titleAr) ? skillGroup.titleAr : skillGroup.title;
    const skills = (isRTL && skillGroup.skillsAr) ? skillGroup.skillsAr : skillGroup.skills;

    const pillsHTML = skills.map(skill =>
      `<span class="skill-pill">${skill}</span>`
    ).join('');

    skillCard.innerHTML = `
      <h3>${title}</h3>
      <div class="skill-pills">
        ${pillsHTML}
      </div>
    `;

    skillsGrid.appendChild(skillCard);

    // Animate in using global observer pattern
    requestAnimationFrame(() => {
      // Check if element is already in viewport - make visible immediately
      const rect = skillCard.getBoundingClientRect();
      const isInViewport = rect.top < window.innerHeight && rect.bottom > 0;

      if (isInViewport) {
        // If already visible, add visible class immediately with a small delay for animation
        setTimeout(() => {
          skillCard.classList.add('visible');
          animatedElementsSet.add(skillCard);
        }, index * 100);
      } else {
        // Otherwise, observe it for when it comes into view
        if (globalAnimationObserver && !animatedElementsSet.has(skillCard)) {
          globalAnimationObserver.observe(skillCard);
        }
        // Fallback: make visible after a delay if observer doesn't trigger
        setTimeout(() => {
          if (!skillCard.classList.contains('visible')) {
            skillCard.classList.add('visible');
            animatedElementsSet.add(skillCard);
          }
        }, 1000 + (index * 100));
      }
    });
  });

  // Ensure all skill cards are observed after creation
  setTimeout(() => {
    const skillCards = document.querySelectorAll('.skill-card:not(.visible)');
    skillCards.forEach(card => {
      if (globalAnimationObserver && !animatedElementsSet.has(card)) {
        globalAnimationObserver.observe(card);
      }
    });
  }, 100);
}

// Languages
function populateLanguages() {
  const languagesList = document.getElementById('languages-list');
  if (!languagesList) return;

  // Clear existing content to prevent duplication
  languagesList.innerHTML = '';

  const isRTL = currentLanguage === 'ar';

  const languages = [
    {
      name: 'Arabic',
      nameAr: 'العربية',
      level: 'Fluent · speak · read · write',
      levelAr: 'طلاقة · تحدث · قراءة · كتابة'
    },
    {
      name: 'English',
      nameAr: 'الإنجليزية',
      level: 'Fluent · speak · read · write',
      levelAr: 'طلاقة · تحدث · قراءة · كتابة'
    },
    {
      name: 'Malayalam',
      nameAr: 'المالايالامية',
      level: 'Fluent · speak',
      levelAr: 'طلاقة · تحدث'
    },
    {
      name: 'Hindi',
      nameAr: 'الهندية',
      level: 'Basic understanding',
      levelAr: 'فهم أساسي'
    },
    {
      name: 'Tamil',
      nameAr: 'التاميلية',
      level: 'Basic understanding',
      levelAr: 'فهم أساسي'
    }
  ];

  languages.forEach((lang, index) => {
    const langItem = document.createElement('div');
    langItem.className = 'language-item';
    langItem.style.transitionDelay = `${index * 80}ms`;

    const name = isRTL && lang.nameAr ? lang.nameAr : lang.name;
    const level = isRTL && lang.levelAr ? lang.levelAr : lang.level;

    langItem.innerHTML = `
      <div class="language-name">${name}</div>
      <div class="language-level">${level}</div>
    `;

    languagesList.appendChild(langItem);

    // Animate in via CSS class (avoids inline transform overriding hover)
    requestAnimationFrame(() => {
      // Check if element is already in viewport - make visible immediately
      const rect = langItem.getBoundingClientRect();
      const isInViewport = rect.top < window.innerHeight && rect.bottom > 0;

      if (isInViewport) {
        // If already visible, add visible class immediately
        setTimeout(() => {
          langItem.classList.add('visible');
        }, index * 80);
      } else {
        // Otherwise, observe it for when it comes into view
        if (globalAnimationObserver && !animatedElementsSet.has(langItem)) {
          globalAnimationObserver.observe(langItem);
        }
        // Fallback: make visible after a delay if observer doesn't trigger
        setTimeout(() => {
          if (!langItem.classList.contains('visible')) {
            langItem.classList.add('visible');
          }
        }, 1000 + (index * 80));
      }
    });
  });

  // Ensure all language items are observed after creation
  setTimeout(() => {
    const langItems = document.querySelectorAll('.language-item:not(.visible)');
    langItems.forEach(item => {
      if (globalAnimationObserver && !animatedElementsSet.has(item)) {
        globalAnimationObserver.observe(item);
      }
    });
  }, 100);
}

// Hobbies
function populateHobbies() {
  const hobbiesList = document.getElementById('hobbies-list');
  if (!hobbiesList) return;

  // Clear existing content to prevent duplication
  hobbiesList.innerHTML = '';

  const isRTL = currentLanguage === 'ar';

  const hobbies = [
    {
      title: 'UI/UX Design Experimentation',
      titleAr: 'تجربة تصميم واجهة المستخدم/تجربة المستخدم',
      description: 'Exploring modern design systems, micro-interactions, and layout ideas for web and mobile.',
      descriptionAr: 'استكشاف أنظمة التصميم الحديثة والتفاعلات الدقيقة وأفكار التخطيط للويب والجوال.'
    },
    {
      title: 'Coding & Logic Challenges',
      titleAr: 'تحديات البرمجة والمنطق',
      description: 'Practicing algorithms, problem-solving, and debugging to sharpen core engineering skills.',
      descriptionAr: 'ممارسة الخوارزميات وحل المشكلات والتصحيح لشحذ المهارات الهندسية الأساسية.'
    },
    {
      title: 'Fitness & Swimming',
      titleAr: 'اللياقة والسباحة',
      description: 'Maintaining focus and discipline through regular workouts and swimming sessions.',
      descriptionAr: 'الحفاظ على التركيز والانضباط من خلال التمارين المنتظمة وجلسات السباحة.'
    },
    {
      title: 'Automobiles & Driving',
      titleAr: 'السيارات والقيادة',
      description: 'Following automotive tech, vehicle design, and enjoying long, mindful drives.',
      descriptionAr: 'متابعة تقنيات السيارات وتصميم المركبات والاستمتاع برحلات طويلة وواعية.'
    },
    {
      title: 'LLM Prompting',
      titleAr: 'هندسة المطالبات للذكاء الاصطناعي',
      description: 'Experimenting with AI tools and prompts to accelerate learning and development.',
      descriptionAr: 'التجربة مع أدوات الذكاء الاصطناعي والمطالبات لتسريع التعلم والتطوير.'
    },
    {
      title: 'Photography',
      titleAr: 'التصوير الفوتوغرافي',
      description: 'Capturing moments, composition, and light to develop a creative visual sense.',
      descriptionAr: 'التقاط اللحظات والتكوين والضوء لتطوير حس بصري إبداعي.'
    }
  ];

  hobbies.forEach((hobby, index) => {
    const hobbyItem = document.createElement('div');
    hobbyItem.className = 'hobby-item';
    hobbyItem.style.transitionDelay = `${index * 80}ms`;

    const title = isRTL && hobby.titleAr ? hobby.titleAr : hobby.title;
    const description = isRTL && hobby.descriptionAr ? hobby.descriptionAr : hobby.description;

    hobbyItem.innerHTML = `
      <div class="hobby-name">${title}</div>
      <div class="hobby-description">${description}</div>
    `;

    hobbiesList.appendChild(hobbyItem);

    // Simple fade-in via CSS class
    requestAnimationFrame(() => {
      // Check if element is already in viewport - make visible immediately
      const rect = hobbyItem.getBoundingClientRect();
      const isInViewport = rect.top < window.innerHeight && rect.bottom > 0;

      if (isInViewport) {
        // If already visible, add visible class immediately
        setTimeout(() => {
          hobbyItem.classList.add('visible');
        }, index * 80);
      } else {
        // Otherwise, observe it for when it comes into view
        if (globalAnimationObserver && !animatedElementsSet.has(hobbyItem)) {
          globalAnimationObserver.observe(hobbyItem);
        }
        // Fallback: make visible after a delay if observer doesn't trigger
        setTimeout(() => {
          if (!hobbyItem.classList.contains('visible')) {
            hobbyItem.classList.add('visible');
          }
        }, 1000 + (index * 80));
      }
    });
  });

  // Ensure all hobby items are observed after creation
  setTimeout(() => {
    const hobbyItems = document.querySelectorAll('.hobby-item:not(.visible)');
    hobbyItems.forEach(item => {
      if (globalAnimationObserver && !animatedElementsSet.has(item)) {
        globalAnimationObserver.observe(item);
      }
    });
  }, 100);
}

// ============================================
// CONTACT FORM
// ============================================

function initContactForm() {
  const contactForm = document.getElementById('contact-form');
  const otherInputGroup = document.getElementById('other-input-group');
  const otherDetailInput = document.getElementById('other-detail');

  if (!contactForm) return;

  // Enforce single-select and handle "Other" reveal
  const categoryCheckboxes = document.querySelectorAll('input[name="category"]');
  const otherCheck = document.getElementById('category-other-check');

  // Prevent clicks inside the "Other" text input from bubbling to the label
  // (which would toggle the checkbox and immediately hide the input again)
  if (otherDetailInput) {
    otherDetailInput.addEventListener('click', e => e.stopPropagation());
    otherDetailInput.addEventListener('mousedown', e => e.stopPropagation());
  }

  categoryCheckboxes.forEach(cb => {
    cb.addEventListener('change', () => {
      if (cb.checked) {
        categoryCheckboxes.forEach(other => { if (other !== cb) other.checked = false; });
      }
      const otherSelected = otherCheck && otherCheck.checked;
      if (otherInputGroup && otherDetailInput) {
        if (otherSelected) {
          otherInputGroup.style.display = 'block';
          otherDetailInput.setAttribute('required', 'required');
          otherDetailInput.focus();
        } else {
          otherInputGroup.style.display = 'none';
          otherDetailInput.removeAttribute('required');
          otherDetailInput.value = '';
        }
      }
    });
  });

  // Handle form submission
  contactForm.addEventListener('submit', (e) => {
    e.preventDefault();

    const name = document.getElementById('name').value.trim();
    const email = document.getElementById('email').value.trim();
    const message = document.getElementById('message').value.trim();
    const selectedCategory = document.querySelector('input[name="category"]:checked')?.value;
    const otherDetail = document.getElementById('other-detail')?.value.trim();

    // Validate form
    if (!name || !email || !message || !selectedCategory) {
      alert('Please fill in all required fields and select a category.');
      return;
    }

    if (selectedCategory === 'other' && !otherDetail) {
      alert('Please specify your category in the "Other" field.');
      otherDetailInput.focus();
      return;
    }

    const categoryLabel = selectedCategory === 'other' ? otherDetail : selectedCategory;

    // Build email subject and body
    const subject = encodeURIComponent(`Contact from ${name} - ${categoryLabel}`);
    const body = encodeURIComponent(
      `Name: ${name}\nEmail: ${email}\nCategory: ${categoryLabel}\n\nMessage:\n${message}`
    );

    // Create mailto link
    const mailtoLink = `mailto:hire.me@ashfaaqkt.com?subject=${subject}&body=${body}`;

    // Open email client
    window.location.href = mailtoLink;

    // Reset form after a short delay
    setTimeout(() => {
      contactForm.reset();
      if (otherInputGroup) {
        otherInputGroup.style.display = 'none';
      }
      if (otherDetailInput) {
        otherDetailInput.removeAttribute('required');
      }
    }, 1000);
  });
}



// ============================================
// SMOOTH SCROLLING FOR ANCHOR LINKS
// ============================================

// Handle all anchor links (hero buttons, footer links, etc.)
function initAnchorLinks() {
  // Use event delegation to handle all anchor links
  document.addEventListener('click', function (e) {
    const anchor = e.target.closest('a[href^="#"]');
    if (!anchor) return;

    const href = anchor.getAttribute('href');

    // Skip if it's an external link, empty, or already handled by nav links
    if (!href || href === '#' || href.startsWith('#!')) {
      return;
    }

    // Skip if it's a nav link (already handled by initNavigation)
    if (anchor.classList.contains('nav-link')) {
      return;
    }

    // Extract page ID from href (e.g., #connect -> connect, #projects -> projects)
    const pageId = href.substring(1); // Remove the #

    // Map common anchor names to page IDs
    const pageMap = {
      'home': 'home',
      'about': 'about',
      'education': 'education',
      'projects': 'projects',
      'expertise': 'expertise',
      'connect': 'connect'
    };

    const targetPage = pageMap[pageId] || pageId;

    // Check if the target page exists
    const targetSection = document.querySelector(`#page-${targetPage}`);
    if (targetSection) {
      e.preventDefault();
      e.stopPropagation();
      navigateToPage(targetPage);
    }
  });
}

// ============================================
// CHATBOT
// ============================================

function initChatbot() {
  const chatbotMessages = document.getElementById('chatbot-messages');
  const chatbotFaqContainer = document.getElementById('chatbot-faq-container');

  if (!chatbotMessages) return;

  function updateChatbotLanguage() {
    // Use the same global language state as the rest of the site
    const lang = (typeof currentLanguage !== 'undefined' && currentLanguage) ? currentLanguage : 'en';
    const t = translations && translations[lang] ? translations[lang] : null;
    if (!t || !t.chatbot) return;

    const welcomeMessage = chatbotMessages.querySelector('.chatbot-message-bot .message-content p');
    if (welcomeMessage) {
      welcomeMessage.textContent = t.chatbot.welcomeMessage;
    }

    if (chatbotFaqContainer && t.chatbot.faqButtons) {
      const faqButtons = chatbotFaqContainer.querySelectorAll('.cb-chip');
      faqButtons.forEach(button => {
        const faqType = button.getAttribute('data-faq');
        const buttonText = t.chatbot.faqButtons[faqType];
        if (buttonText) {
          const span = button.querySelector('span:not(.cb-chip-icon)');
          if (span) span.textContent = buttonText;
        }
      });
    }
  }

  // Chatbot Toggle Logic
  const chatbotToggle = document.getElementById('chatbot-toggle');
  const chatbotContainer = document.getElementById('chatbot-container');
  const chatbotMinimize = document.getElementById('chatbot-minimize');
  const backToTop = document.getElementById('back-to-top');

  const chatbotBackdrop = document.getElementById('chatbot-backdrop');

  function openChatbot() {
    chatbotContainer.classList.add('open');
    chatbotContainer.setAttribute('aria-hidden', 'false');
    chatbotToggle.classList.add('hidden');
    if (backToTop) backToTop.classList.add('chatbot-open');
    // Blur + lock scroll
    if (chatbotBackdrop) chatbotBackdrop.classList.add('active');
    document.body.classList.add('no-scroll');
    document.documentElement.classList.add('no-scroll');
  }

  function closeChatbot() {
    chatbotContainer.classList.remove('open');
    chatbotContainer.setAttribute('aria-hidden', 'true');
    // Remove blur + restore scroll immediately
    if (chatbotBackdrop) chatbotBackdrop.classList.remove('active');
    document.body.classList.remove('no-scroll');
    document.documentElement.classList.remove('no-scroll');
    // Show toggle after shrink animation
    setTimeout(() => {
      chatbotToggle.classList.remove('hidden');
      if (backToTop) backToTop.classList.remove('chatbot-open');
    }, 420);
  }

  if (chatbotToggle && chatbotContainer) {
    chatbotToggle.addEventListener('click', (e) => { e.preventDefault(); openChatbot(); });
    if (chatbotMinimize) {
      chatbotMinimize.addEventListener('click', (e) => { e.preventDefault(); closeChatbot(); });
    }
    // Tap backdrop to close
    if (chatbotBackdrop) {
      chatbotBackdrop.addEventListener('click', closeChatbot);
    }
  }

  if (chatbotFaqContainer) {
    const faqButtons = chatbotFaqContainer.querySelectorAll('.cb-chip');
    faqButtons.forEach(button => {
      button.addEventListener('click', (e) => {
        e.preventDefault();
        const faqType = button.getAttribute('data-faq');
        const span = button.querySelector('span:not(.cb-chip-icon)');
        const question = span ? span.textContent.trim() : button.textContent.trim();
        window.chatbotHandleFaqClick && window.chatbotHandleFaqClick(faqType, question);
      });
    });
  }

  updateChatbotLanguage();
  window.updateChatbotLanguage = updateChatbotLanguage;
}

// Main global FAQ click handler
window.chatbotHandleFaqClick = function (faqType, questionText) {
  const chatbotMessages = document.getElementById('chatbot-messages');
  if (!chatbotMessages || !faqType || !questionText) return;

  // Add user question
  const userMsg = document.createElement('div');
  userMsg.className = 'chatbot-message chatbot-message-user';
  const userContent = document.createElement('div');
  userContent.className = 'message-content';
  const userP = document.createElement('p');
  userP.textContent = questionText;
  userContent.appendChild(userP);
  userMsg.appendChild(userContent);
  chatbotMessages.appendChild(userMsg);

  // Determine answer using global translations data (same as the rest of the site)
  let answerText;
  try {
    const lang = (typeof currentLanguage !== 'undefined' && currentLanguage) ? currentLanguage : 'en';
    const t = translations && translations[lang] ? translations[lang] : null;
    const answers = t && t.chatbot && t.chatbot.answers ? t.chatbot.answers : {};
    const defaultError = lang === 'ar'
      ? 'عذراً، لا أملك إجابة على هذا السؤال.'
      : 'Sorry, I don\'t have an answer for that question.';
    answerText = answers[faqType] || defaultError;
  } catch (e) {
    // Absolute fallback – should rarely be hit
    answerText = 'Thanks for your question! Please check the corresponding section in the portfolio for full details.';
  }

  // Add bot answer after a short delay
  setTimeout(() => {
    const botMsg = document.createElement('div');
    botMsg.className = 'chatbot-message chatbot-message-bot';
    const botContent = document.createElement('div');
    botContent.className = 'message-content';
    botContent.innerHTML = answerText;
    botMsg.appendChild(botContent);
    chatbotMessages.appendChild(botMsg);
    chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
  }, 300);
};

// ============================================
// PORTFOLIO SUMMARY MODAL
// ============================================

function initFYPModal() {
  const overlay  = document.getElementById('fyp-modal-overlay');
  const closeBtn = document.getElementById('fyp-modal-close');
  const openBtn  = document.getElementById('fyp-readmore-btn');
  if (!overlay || !openBtn) return;

  function openFYP() {
    overlay.classList.add('active');
    overlay.setAttribute('aria-hidden', 'false');
    document.body.classList.add('no-scroll');
    document.documentElement.classList.add('no-scroll');
  }

  function closeFYP() {
    overlay.classList.remove('active');
    overlay.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('no-scroll');
    document.documentElement.classList.remove('no-scroll');
  }

  openBtn.addEventListener('click', openFYP);
  if (closeBtn) closeBtn.addEventListener('click', closeFYP);

  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeFYP();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && overlay.classList.contains('active')) closeFYP();
  });

  // Sync data-en/data-ar labels inside modal on language change
  document.addEventListener('languageChanged', () => {
    const lang = currentLanguage || 'en';
    overlay.querySelectorAll('[data-en][data-ar]').forEach(el => {
      const text = el.getAttribute(lang === 'ar' ? 'data-ar' : 'data-en');
      if (text && el.children.length === 0) el.textContent = text;
    });
  });
}

function initPortfolioSummaryModal() {
  const modal = document.getElementById('portfolio-summary-modal');
  const modalBtn = document.getElementById('portfolio-summary-btn');
  const modalClose = document.getElementById('portfolio-summary-modal-close');
  const modalOverlay = document.getElementById('portfolio-summary-modal-overlay');

  if (!modal || !modalBtn) return;

  function openModal() {
    modal.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
    document.documentElement.classList.add('modal-open');
  }

  function closeModal() {
    modal.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
    document.documentElement.classList.remove('modal-open');
  }

  // Open modal on button click
  modalBtn.addEventListener('click', (e) => {
    e.preventDefault();
    openModal();
  });

  // Close modal on close button click
  if (modalClose) {
    modalClose.addEventListener('click', closeModal);
  }

  // Close modal on overlay click
  if (modalOverlay) {
    modalOverlay.addEventListener('click', closeModal);
  }

  // Close modal when sub-links are clicked
  modal.querySelectorAll('.portfolio-summary-link').forEach(link => {
    link.addEventListener('click', closeModal);
  });

  // Close modal on Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.getAttribute('aria-hidden') === 'false') {
      closeModal();
    }
  });
}

// ============================================
// AUTHENTICATION & ADMIN
// ============================================

function initAuth() {
  const authBtn = document.getElementById('auth-btn');
  const adminBtn = document.getElementById('admin-login-link');
  
  const authModal = document.getElementById('auth-modal');
  const closeAuth = document.getElementById('auth-modal-close');
  const overlayAuth = document.getElementById('auth-modal-overlay');
  
  const tabLogin = document.getElementById('tab-login');
  const tabRegister = document.getElementById('tab-register');
  const formLogin = document.getElementById('form-login');
  const formRegister = document.getElementById('form-register');

  // Initializing enhanced form features
  function initEnhancedForm() {
    // 1. Password Visibility Toggle
    document.querySelectorAll('.password-toggle').forEach(btn => {
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        const input = btn.parentElement.querySelector('input');
        const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
        input.setAttribute('type', type);
        btn.style.color = type === 'text' ? 'var(--color-accent-primary)' : 'var(--color-text-secondary)';
      });
    });

    // 2. Generalized Custom Select Logic
    document.querySelectorAll('.custom-select').forEach(customSelect => {
      const trigger = customSelect.querySelector('.custom-select-trigger');
      const options = customSelect.querySelectorAll('.custom-option');
      const hiddenInput = customSelect.querySelector('input[type="hidden"]');
      const triggerSpan = trigger.querySelector('span');

      // Specialized logic for Category "Other"
      const isCategorySelect = customSelect.id === 'reg-category-custom';
      const otherGroup = document.getElementById('other-category-group');
      const otherInput = document.getElementById('reg-category-other');

      trigger.addEventListener('click', (e) => {
        e.stopPropagation();
        // Close other custom selects first
        document.querySelectorAll('.custom-select').forEach(cs => {
          if (cs !== customSelect) cs.classList.remove('active');
        });
        customSelect.classList.toggle('active');
      });

      options.forEach(opt => {
        opt.addEventListener('click', (e) => {
          e.stopPropagation();
          const val = opt.getAttribute('data-value');
          hiddenInput.value = val;
          triggerSpan.textContent = opt.textContent;
          customSelect.classList.remove('active');
          options.forEach(o => o.classList.remove('selected'));
          opt.classList.add('selected');

          // Handle "Other" field for Category select
          if (isCategorySelect) {
            if (val === 'Other') {
              otherGroup.style.display = 'flex';
              if (otherInput) otherInput.setAttribute('required', 'required');
            } else {
              otherGroup.style.display = 'none';
              if (otherInput) {
                otherInput.removeAttribute('required');
                otherInput.value = '';
              }
            }
          }
        });
      });
    });

    document.addEventListener('click', () => {
      document.querySelectorAll('.custom-select').forEach(cs => cs.classList.remove('active'));
    });

    // 3. Phone Number Validation
    const phoneInput = document.getElementById('reg-phone');
    if (phoneInput) {
      phoneInput.addEventListener('input', (e) => {
        let val = e.target.value.replace(/\D/g, '');
        if (val.length > 10) val = val.slice(0, 10);
        e.target.value = val;
      });
    }
  }
  initEnhancedForm();

  // Icon SVGs reused in updateAuthState
  const iconSignIn = `<svg class="auth-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>`;
  const iconLoggedIn = `<svg class="auth-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/></svg>`;

  // Set auth state — icon-only button with tooltip
  function updateAuthState() {
    const msmAuthBtn = document.getElementById('msm-auth-btn');
    const msmLabelEl = msmAuthBtn ? msmAuthBtn.querySelector('.msm-auth-label') : null;

    if (!authBtn) return;
    try {
      const token = localStorage.getItem('portfolio_token');
      const userStr = localStorage.getItem('portfolio_user');
      if (token && userStr) {
        const user = JSON.parse(userStr);
        const label = currentLanguage === 'ar' ? `مرحباً ${user.name}` : `Hello ${user.name}`;
        authBtn.setAttribute('aria-label', label);
        authBtn.dataset.loggedIn = 'true';
        authBtn.innerHTML = `${iconLoggedIn}<span class="auth-tooltip">${label}</span><span class="mobile-nav-label">${user.name}</span>`;
        
        if (msmAuthBtn) {
          msmAuthBtn.setAttribute('aria-label', label);
          msmAuthBtn.dataset.loggedIn = 'true';
          if (msmLabelEl) msmLabelEl.textContent = user.name;
        }
        return;
      }
    } catch (err) {
      localStorage.removeItem('portfolio_token');
      localStorage.removeItem('portfolio_user');
    }
    const label = currentLanguage === 'ar' ? 'تسجيل الدخول' : 'Sign In';
    const mobileLabel = currentLanguage === 'ar' ? 'تسجيل الدخول / إنشاء حساب' : 'Sign In / Sign Up';
    authBtn.setAttribute('aria-label', label);
    authBtn.dataset.loggedIn = 'false';
    authBtn.innerHTML = `${iconSignIn}<span class="auth-tooltip">${label}</span><span class="mobile-nav-label">${mobileLabel}</span>`;
    
    if (msmAuthBtn) {
      msmAuthBtn.setAttribute('aria-label', label);
      msmAuthBtn.dataset.loggedIn = 'false';
      if (msmLabelEl) msmLabelEl.textContent = label;
    }
  }
  updateAuthState();
  
  // Expose function so lang toggle updates 'Sign in' text correctly when logged out
  window.updateAuthLangState = updateAuthState;
  
  function openModal(modalEl) {
    if (modalEl) {
      modalEl.setAttribute('aria-hidden', 'false');
      document.body.classList.add('no-scroll');
      document.documentElement.classList.add('no-scroll');
    }
  }
  function hideModal(modalEl) {
    if (modalEl) {
      modalEl.setAttribute('aria-hidden', 'true');
      document.body.classList.remove('no-scroll', 'modal-open');
      document.documentElement.classList.remove('no-scroll', 'modal-open');
    }
  }

  // Export openAuthModal for global use — accepts optional 'login' or 'signup' tab name
  window.openAuthModal = (tab) => {
    openModal(authModal);
    if (tab === 'signup' || tab === 'register') {
      if (tabRegister) tabRegister.click();
    } else {
      if (tabLogin) tabLogin.click();
    }
  };
  
  if (authBtn) {
    authBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (authBtn.dataset.loggedIn === 'true') {
        // Already logged in — clicking signs out
        try {
          const u = JSON.parse(localStorage.getItem('portfolio_user') || '{}');
          const firstName = (u.name || '').split(' ')[0];
          if (firstName) showGoodbyeToast(firstName);
        } catch (_) {}
        localStorage.removeItem('portfolio_token');
        localStorage.removeItem('portfolio_user');
        updateAuthState();
      } else {
        openModal(authModal);
      }
    });
  }

  const msmAuthBtn = document.getElementById('msm-auth-btn');
  if (msmAuthBtn) {
    msmAuthBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (typeof window.closeMobileSideMenu === 'function') {
        window.closeMobileSideMenu();
      }
      if (msmAuthBtn.dataset.loggedIn === 'true') {
        try {
          const u = JSON.parse(localStorage.getItem('portfolio_user') || '{}');
          const firstName = (u.name || '').split(' ')[0];
          if (firstName) showGoodbyeToast(firstName);
        } catch (_) {}
        localStorage.removeItem('portfolio_token');
        localStorage.removeItem('portfolio_user');
        updateAuthState();
      } else {
        openModal(authModal);
      }
    });
  }

  if (adminBtn) {
    adminBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      openAdminPopup();
    });
    adminBtn.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        openAdminPopup();
      }
    });
  }

  /* ── Admin Gate Popup ── */
  const admPopup      = document.getElementById('adm-popup');
  const admPopupClose = document.getElementById('adm-popup-close');
  const admPopupOverlay = document.getElementById('adm-popup-overlay');
  const admPopupForm  = document.getElementById('adm-popup-form');
  const admPopupPass  = document.getElementById('adm-popup-pass');
  const admPopupEye   = document.getElementById('adm-popup-eye');
  const admPopupErr   = document.getElementById('adm-popup-err');
  const admPopupSubmit = document.getElementById('adm-popup-submit');

  function openAdminPopup() {
    if (!admPopup) return;
    admPopup.setAttribute('aria-hidden', 'false');
    document.body.classList.add('no-scroll');
    admPopupErr.textContent = '';
    admPopupPass.value = '';
    setTimeout(() => admPopupPass.focus(), 120);
  }

  function closeAdminPopup() {
    if (!admPopup) return;
    admPopup.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('no-scroll');
  }

  if (admPopupClose) admPopupClose.addEventListener('click', closeAdminPopup);
  if (admPopupOverlay) admPopupOverlay.addEventListener('click', closeAdminPopup);

  /* Eye toggle */
  if (admPopupEye) {
    admPopupEye.addEventListener('click', () => {
      const isPass = admPopupPass.type === 'password';
      admPopupPass.type = isPass ? 'text' : 'password';
      admPopupEye.querySelector('.eye-open').style.display  = isPass ? 'none' : '';
      admPopupEye.querySelector('.eye-closed').style.display = isPass ? '' : 'none';
    });
  }

  /* Submit — verify password then redirect */
  if (admPopupForm) {
    admPopupForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const pw = admPopupPass.value;
      if (!pw) return;
      admPopupErr.textContent = '';
      admPopupSubmit.disabled = true;
      admPopupSubmit.querySelector('.adm-popup-submit-text').textContent = 'Verifying…';
      admPopupSubmit.querySelector('.adm-popup-submit-arrow').hidden = true;
      admPopupSubmit.querySelector('.adm-popup-spinner').hidden = false;

      try {
        const res = await fetch(`${API_BASE_URL}/admin/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password: pw })
        });
        const data = await res.json();
        if (res.ok) {
          localStorage.setItem('admin_token', data.token);
          admPopupSubmit.querySelector('.adm-popup-submit-text').textContent = 'Redirecting…';
          setTimeout(() => { window.location.href = 'admin.html'; }, 300);
        } else {
          admPopupErr.textContent = data.message || 'Incorrect password.';
          admPopupPass.value = '';
          admPopupPass.focus();
          resetSubmitBtn();
        }
      } catch (_) {
        admPopupErr.textContent = 'Server error. Is the backend running?';
        resetSubmitBtn();
      }
    });
  }

  function resetSubmitBtn() {
    if (!admPopupSubmit) return;
    admPopupSubmit.disabled = false;
    admPopupSubmit.querySelector('.adm-popup-submit-text').textContent = 'Enter Dashboard';
    admPopupSubmit.querySelector('.adm-popup-submit-arrow').hidden = false;
    admPopupSubmit.querySelector('.adm-popup-spinner').hidden = true;
  }
  
  [closeAuth, overlayAuth].forEach(el => el && el.addEventListener('click', () => hideModal(authModal)));
  
  // Tabs Toggle
  if (tabLogin && tabRegister) {
    tabLogin.addEventListener('click', () => {
      tabLogin.classList.add('active');
      tabRegister.classList.remove('active');
      formLogin.classList.add('active');
      formLogin.style.display = 'flex';
      formRegister.classList.remove('active');
      formRegister.style.display = 'none';
      if(document.getElementById('login-error')) document.getElementById('login-error').textContent = '';
    });
    tabRegister.addEventListener('click', () => {
      tabRegister.classList.add('active');
      tabLogin.classList.remove('active');
      formRegister.classList.add('active');
      formRegister.style.display = 'flex';
      formLogin.classList.remove('active');
      formLogin.style.display = 'none';
      if(document.getElementById('reg-error')) document.getElementById('reg-error').textContent = '';
    });
  }
  
  // Form Submit Login
  if (formLogin) {
    formLogin.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('login-email').value;
      const pw = document.getElementById('login-password').value;
      const errorEl = document.getElementById('login-error');
      const submitBtn = formLogin.querySelector('button[type="submit"]');
      
      errorEl.textContent = '';
      submitBtn.classList.add('btn-loading');
      
      try {
        const res = await fetch(`${API_BASE_URL}/auth/login`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ email, password: pw })
        });
        const data = await res.json();
        if (res.ok) {
          localStorage.setItem('portfolio_token', data.token);
          localStorage.setItem('portfolio_user', JSON.stringify(data.user));
          updateAuthState();
          hideModal(authModal);
          const firstName = (data.user?.name || '').split(' ')[0];
          if (firstName) showWelcomeToast(firstName, false);
          if (window.pendingPdfLink) {
            const pending = window.pendingPdfLink;
            window.pendingPdfLink = null;
            window.openProtectedPDF(pending, data.token);
          }
        } else {
          errorEl.textContent = data.message;
        }
      } catch (err) {
        errorEl.textContent = 'Server error. Is the backend running?';
      } finally {
        submitBtn.classList.remove('btn-loading');
      }
    });
  }

  // Form Submit Register
  if (formRegister) {
    formRegister.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errorEl = document.getElementById('reg-error');
      const name = document.getElementById('reg-name').value;
      const email = document.getElementById('reg-email').value;
      const phoneNumber = document.getElementById('reg-phone').value;
      if (phoneNumber && phoneNumber.length !== 10) {
        errorEl.textContent = 'Phone number must be exactly 10 digits.';
        return;
      }
      
      const phoneCode = document.getElementById('reg-phone-code').value || '+91';
      const phone = phoneNumber ? `${phoneCode}${phoneNumber}` : '';
      
      const categoryVal = document.getElementById('reg-category').value;
      const categoryOther = document.getElementById('reg-category-other').value;
      const category = categoryVal === 'Other' ? categoryOther : categoryVal;
      
      const company = document.getElementById('reg-company').value;
      const pw = document.getElementById('reg-password').value;
      
      const submitBtn = formRegister.querySelector('button[type="submit"]');
      errorEl.textContent = '';
      submitBtn.classList.add('btn-loading');
      
      try {
        const res = await fetch(`${API_BASE_URL}/auth/register`, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ name, email, phone, category, company, password: pw })
        });
        const data = await res.json();
        if (res.ok) {
          localStorage.setItem('portfolio_token', data.token);
          localStorage.setItem('portfolio_user', JSON.stringify(data.user));
          updateAuthState();
          hideModal(authModal);
          const firstName = (data.user?.name || '').split(' ')[0];
          if (firstName) showWelcomeToast(firstName, true);
          if (window.pendingPdfLink) {
            const pending = window.pendingPdfLink;
            window.pendingPdfLink = null;
            window.openProtectedPDF(pending, data.token);
          }
        } else {
          errorEl.textContent = data.message;
        }
      } catch (err) {
        errorEl.textContent = 'Server error. Is the backend running?';
      } finally {
        submitBtn.classList.remove('btn-loading');
      }
    });
  }

  // PDF interception moved to global DOMContentLoaded for better reliability
}
