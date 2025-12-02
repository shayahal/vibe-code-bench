"""
Predefined prompts for website creation.
"""

# System prompt - defines the agent's role
SYSTEM_PROMPT = """You are an expert web developer. Generate complete, functional websites based on user requirements.

CRITICAL: You MUST respond with ONLY a valid JSON object. No markdown, no explanations, just pure JSON.

The JSON format must be exactly:
{
  "files": {
    "filename.ext": "complete file content here",
    "another_file.ext": "complete file content here"
  }
}

Requirements:
- Respond with ONLY valid JSON, no markdown code blocks, no explanations
- Include ALL necessary files for a complete, functional website
- Ensure there is exactly ONE file named "main.py" in the response
- Use proper file extensions (.html, .css, .js, .py, etc.)
- Provide complete, working code in each file
- Escape JSON properly (newlines as \\n, quotes as \\", etc.)
- Each file's content should be a complete, functional file

Example response format:
{"files": {"index.html": "<!DOCTYPE html>\\n<html>...</html>", "styles.css": "body { margin: 0; }", "script.js": "console.log('Hello');", "main.py": "print('Hello')"}}"""

# User prompt - what to create
USER_PROMPT = """Create a complete, professional pizzeria website with the following features:

**Website Sections (ALL must be fully implemented):**
1. Header with sticky navigation (Home, Menu, About, Contact) - smooth scroll to sections
2. Hero section with pizzeria name, compelling tagline, and call-to-action button
3. Menu section with AT LEAST 6 different pizza items, each with:
   - Pizza name
   - Detailed description
   - Price (formatted as currency)
   - Large emoji or image placeholder
   - "Add to Cart" button for each item
   - Grid layout showing all pizzas nicely
4. About section with detailed pizzeria story (at least 3-4 paragraphs)
5. Contact section with:
   - Full address
   - Phone number
   - Email
   - Hours of operation (detailed schedule)
   - Fully functional contact form with validation (name, email, message fields)
6. Footer with social media links and additional info

**Design Requirements:**
- Warm, appetizing color scheme (reds, oranges, warm tones) with good contrast
- Modern, professional layout using CSS Grid or Flexbox
- Fully responsive design (mobile-first, works perfectly on all screen sizes)
- Beautiful typography with proper font sizes and spacing
- Smooth animations and transitions
- Hover effects on buttons and menu items
- Professional spacing and padding throughout

**JavaScript Functionality (MUST be implemented):**
- Smooth scrolling navigation
- Menu filtering/search functionality (filter by name or price)
- Shopping cart functionality:
  - Add items to cart
  - Display cart count in header
  - Cart sidebar or modal showing items
  - Remove items from cart
  - Calculate total price
  - Cart persists in localStorage
- Contact form validation:
  - Validate email format
  - Check all fields are filled
  - Show success/error messages
  - Prevent form submission if invalid
- Interactive elements (hover effects, click animations)

**Python File Requirements:**
- Create a functional main.py that can serve the website from the current directory
- Use Python's built-in http.server module (simplest and most reliable)
- OR use Flask but serve files as static files (NOT templates):
  - Use send_file() or send_from_directory() to serve index.html, styles.css, script.js
  - Do NOT use render_template() - files are in same directory, not in templates folder
  - Set up routes: / serves index.html, /styles.css serves styles.css, /script.js serves script.js
- Server must serve files from the same directory where main.py is located
- Include proper error handling and clear instructions
- Server should be runnable with: python main.py
- Add comments explaining how to run it
- Make it simple but functional - the website must work when you run: python main.py

**Technical Requirements:**
- Semantic HTML5 with proper structure
- Modern CSS with Grid/Flexbox for layouts
- Vanilla JavaScript (no frameworks, but can use modern ES6+)
- No external dependencies for frontend (except what's needed for Python server)
- Well-commented, production-quality code
- All code must be complete and functional

**Files to create:**
- index.html (complete page with all sections, properly structured)
- styles.css (comprehensive styling, responsive, professional)
- script.js (all interactivity: cart, filtering, form validation, smooth scroll)
- main.py (Flask server or http.server that serves the website)

**IMPORTANT:**
- The website must be fully functional and runnable
- All JavaScript features must work
- The Python server must be able to serve the site
- Everything must be complete - no placeholders or "TODO" comments
- Make it look like a real, professional pizzeria website

Respond with ONLY a JSON object in this exact format:
{"files": {"index.html": "...", "styles.css": "...", "script.js": "...", "main.py": "..."}}"""
