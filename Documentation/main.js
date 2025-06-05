// Theme Toggle
function toggleTheme() {
    const body = document.body;
    const currentTheme = body.getAttribute('data-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    body.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);

    // Update icon
    const icon = document.querySelector('.theme-toggle i');
    icon.className = newTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
}

// Load saved theme
window.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.body.setAttribute('data-theme', savedTheme);

    const icon = document.querySelector('.theme-toggle i');
    if (icon) {
        icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }

    // Initialize API navigation
    initializeApiNavigation();

    // Initialize Prism.js if available
    if (typeof Prism !== 'undefined') {
        Prism.highlightAll();
    }
});

// Tab functionality
function showTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });

    // Remove active class from all buttons
    document.querySelectorAll('.tab-button').forEach(button => {
        button.classList.remove('active');
    });

    // Show selected tab
    const selectedTab = document.getElementById(tabName);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Activate selected button
    if (event && event.target) {
        event.target.classList.add('active');
    }
}

// Installation tab functionality
function showInstallTab(tabName) {
    // Hide all tab contents
    document.querySelectorAll('#npm, #yarn, #pnpm').forEach(content => {
        content.classList.remove('active');
    });

    // Remove active class from all buttons in installation section
    if (event && event.target && event.target.parentElement) {
        event.target.parentElement.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
        });
    }

    // Show selected tab
    const selectedTab = document.getElementById(tabName);
    if (selectedTab) {
        selectedTab.classList.add('active');
    }

    // Activate selected button
    if (event && event.target) {
        event.target.classList.add('active');
    }
}

// Copy code functionality
function copyCode(button) {
    const codeBlock = button.nextElementSibling.querySelector('code');
    if (!codeBlock) return;

    const text = codeBlock.textContent;

    // Use modern clipboard API if available, fallback to older method
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => {
            showCopySuccess(button);
        }).catch(err => {
            console.error('Failed to copy text: ', err);
            fallbackCopyTextToClipboard(text, button);
        });
    } else {
        fallbackCopyTextToClipboard(text, button);
    }
}

// Fallback copy method for older browsers
function fallbackCopyTextToClipboard(text, button) {
    const textArea = document.createElement("textarea");
    textArea.value = text;

    // Avoid scrolling to bottom
    textArea.style.top = "0";
    textArea.style.left = "0";
    textArea.style.position = "fixed";

    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showCopySuccess(button);
        }
    } catch (err) {
        console.error('Fallback: Oops, unable to copy', err);
    }

    document.body.removeChild(textArea);
}

// Show copy success feedback
function showCopySuccess(button) {
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-check"></i>';
    button.style.background = 'var(--success-color)';
    button.style.color = 'white';

    setTimeout(() => {
        button.innerHTML = originalText;
        button.style.background = '';
        button.style.color = '';
    }, 2000);
}

// API Navigation functions
function toggleApiSection(sectionId) {
    const section = document.getElementById(sectionId);
    const header = event.currentTarget;

    if (!section || !header) return;

    if (section.classList.contains('collapsed')) {
        section.classList.remove('collapsed');
        header.classList.remove('collapsed');
    } else {
        section.classList.add('collapsed');
        header.classList.add('collapsed');
    }
}

function showApiContent(contentId) {
    // Hide all content sections
    document.querySelectorAll('.api-content-section').forEach(section => {
        section.classList.remove('active');
    });

    // Remove active class from all nav links
    document.querySelectorAll('.api-nav-items a').forEach(link => {
        link.classList.remove('active');
    });

    // Show selected content
    const content = document.getElementById(contentId);
    if (content) {
        content.classList.add('active');
    }

    // Activate selected nav link
    if (event && event.target) {
        event.target.classList.add('active');
    }

    // Scroll to top of API content area
    const apiContent = document.querySelector('.api-content');
    if (apiContent) {
        apiContent.scrollTop = 0;
    }
}

// Initialize API navigation
function initializeApiNavigation() {
    // Show first section by default
    const firstSection = document.querySelector('.api-content-section');
    if (firstSection) {
        firstSection.classList.add('active');
    }

    // Activate first nav link
    const firstNavLink = document.querySelector('.api-nav-items a');
    if (firstNavLink) {
        firstNavLink.classList.add('active');
    }

    // Add click event listeners to all API navigation links
    document.querySelectorAll('.api-nav-items a').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = link.getAttribute('href').substring(1);
            showApiContentById(targetId);
        });
    });

    // Add click event listeners to API section headers
    document.querySelectorAll('.api-nav-header').forEach(header => {
        header.addEventListener('click', (e) => {
            const sectionId = header.getAttribute('onclick').match(/toggleApiSection\('(.+)'\)/)[1];
            toggleApiSectionById(sectionId);
        });
    });
}

// Helper function to show API content by ID (without event object)
function showApiContentById(contentId) {
    // Hide all content sections
    document.querySelectorAll('.api-content-section').forEach(section => {
        section.classList.remove('active');
    });

    // Remove active class from all nav links
    document.querySelectorAll('.api-nav-items a').forEach(link => {
        link.classList.remove('active');
    });

    // Show selected content
    const content = document.getElementById(contentId);
    if (content) {
        content.classList.add('active');
    }

    // Activate corresponding nav link
    const navLink = document.querySelector(`a[href="#${contentId}"]`);
    if (navLink) {
        navLink.classList.add('active');
    }

    // Scroll to top of API content area
    const apiContent = document.querySelector('.api-content');
    if (apiContent) {
        apiContent.scrollTop = 0;
    }
}

// Helper function to toggle API section by ID (without event object)
function toggleApiSectionById(sectionId) {
    const section = document.getElementById(sectionId);
    const header = document.querySelector(`[onclick*="toggleApiSection('${sectionId}')"]`);

    if (!section || !header) return;

    if (section.classList.contains('collapsed')) {
        section.classList.remove('collapsed');
        header.classList.remove('collapsed');
    } else {
        section.classList.add('collapsed');
        header.classList.add('collapsed');
    }
}

// Method expansion (legacy - keeping for compatibility)
function toggleMethod(header) {
    const content = header.nextElementSibling;
    const icon = header.querySelector('.expand-icon');

    if (!content) return;

    if (content.classList.contains('expanded')) {
        content.classList.remove('expanded');
        header.classList.remove('expanded');
    } else {
        content.classList.add('expanded');
        header.classList.add('expanded');
    }
}

// Smooth scrolling for navigation links
function initializeSmoothScrolling() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            const href = this.getAttribute('href');

            // Skip API navigation links (they have their own handler)
            if (this.closest('.api-nav-items')) {
                return;
            }

            e.preventDefault();
            const target = document.querySelector(href);
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
}

// Search functionality (placeholder for future implementation)
function initializeSearch() {
    // Add search functionality here if needed
    // This could include:
    // - Searching through API methods
    // - Filtering navigation items
    // - Highlighting search results
}

// Mobile menu toggle (if needed for responsive design)
function toggleMobileMenu() {
    const navLinks = document.querySelector('.nav-links');
    if (navLinks) {
        navLinks.classList.toggle('mobile-active');
    }
}

// Keyboard navigation support
function initializeKeyboardNavigation() {
    document.addEventListener('keydown', (e) => {
        // ESC key to close any open modals or menus
        if (e.key === 'Escape') {
            // Close mobile menu if open
            const navLinks = document.querySelector('.nav-links.mobile-active');
            if (navLinks) {
                navLinks.classList.remove('mobile-active');
            }
        }

        // Ctrl/Cmd + K for search (placeholder)
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            // Implement search functionality here
            console.log('Search functionality not yet implemented');
        }
    });
}

// Performance: Lazy load sections that are not immediately visible
function initializeLazyLoading() {
    const apiSections = document.querySelectorAll('.api-content-section:not(.active)');

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Section is now visible, can perform any lazy loading here
                observer.unobserve(entry.target);
            }
        });
    });

    apiSections.forEach(section => {
        observer.observe(section);
    });
}

// Enhanced initialization
window.addEventListener('DOMContentLoaded', () => {
    // Core functionality
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.body.setAttribute('data-theme', savedTheme);

    const icon = document.querySelector('.theme-toggle i');
    if (icon) {
        icon.className = savedTheme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
    }

    // Initialize all functionality
    initializeApiNavigation();
    initializeSmoothScrolling();
    initializeKeyboardNavigation();
    initializeLazyLoading();

    // Initialize syntax highlighting
    if (typeof Prism !== 'undefined') {
        Prism.highlightAll();
    }

    // Add loading states and animations
    document.body.classList.add('loaded');
});

// Error handling
window.addEventListener('error', (e) => {
    console.error('JavaScript error:', e.error);
    // Could implement user-friendly error reporting here
});

// Performance monitoring (optional)
if ('performance' in window) {
    window.addEventListener('load', () => {
        setTimeout(() => {
            const perfData = performance.getEntriesByType('navigation')[0];
            console.log(`Page load time: ${perfData.loadEventEnd - perfData.loadEventStart}ms`);
        }, 0);
    });
}