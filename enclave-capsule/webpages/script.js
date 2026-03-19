document.addEventListener('DOMContentLoaded', () => {
    const sections = Array.from(document.querySelectorAll('.section[id]'));
    const navLinks = Array.from(document.querySelectorAll('#nav .nav-link'));
    const hashLinks = navLinks.filter(link => {
        const href = link.getAttribute('href') || '';
        return href.startsWith('#');
    });

    // Smooth scrolling for in-page sidebar links only.
    hashLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            const href = link.getAttribute('href');
            if (!href || !href.startsWith('#')) {
                return;
            }

            e.preventDefault();
            const targetId = href.substring(1);
            const targetSection = document.getElementById(targetId);

            if (targetSection) {
                window.scrollTo({
                    top: targetSection.offsetTop - 50,
                    behavior: 'smooth'
                });
            }
        });
    });

    const updateActiveNav = () => {
        if (hashLinks.length === 0 || sections.length === 0) {
            return;
        }

        let current = sections[0].getAttribute('id');

        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            if (window.scrollY >= (sectionTop - 150)) {
                current = section.getAttribute('id');
            }
        });

        hashLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${current}`) {
                link.classList.add('active');
            }
        });
    };

    window.addEventListener('scroll', updateActiveNav, { passive: true });
    updateActiveNav();
});
