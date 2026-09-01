# 🛡️ WebShield

A modern website security analyzer that evaluates common web security practices, HTTP security headers, HTTPS configuration, cookies, redirects, and server exposure to provide an easy-to-understand security score with actionable recommendations.

> Built with **Next.js**, **TypeScript**, and **Tailwind CSS**.

---

## 🌐 Production

WebShield is deployed at:

https://webshield-zpv1.onrender.com

The optional FastAPI backend is deployed separately through `render.yaml`.

---

## ✨ Features

- 🔒 HTTPS Detection
- 🛡️ Security Header Analysis
- 📊 Security Score & Grade
- ⚠️ Vulnerability Summary
- 💡 Actionable Security Recommendations
- 🍪 Cookie Security Analysis
- 🔀 Redirect Chain Analysis
- 📄 Raw HTTP Header Viewer
- ⚡ Fast Website Scanning
- 📱 Responsive User Interface

---

## 🔐 Production Security

The production scanner includes:

- SSRF protection for private, loopback, metadata, reserved, and internal network targets
- Redirect-by-redirect target validation
- Process-level DNS egress protection for server-side HTTP requests
- Distributed scan rate limiting with Upstash Redis
- Basic Authentication for dashboard, monitoring, and scan-history APIs
- Secure response headers
- Restricted FastAPI CORS policy

Before production deployment, configure these server-side environment variables:

```text
ADMIN_USERNAME
ADMIN_PASSWORD
UPSTASH_REDIS_REST_URL
UPSTASH_REDIS_REST_TOKEN
FRONTEND_ORIGIN
WEBSHIELD_INTERNAL_API_SECRET
```

Never expose admin or Redis credentials through `NEXT_PUBLIC_*` variables.

---

## 🛠️ Tech Stack

- Next.js
- React
- TypeScript
- Tailwind CSS
- Node.js
- FastAPI
- Python
- Upstash Redis

---

## 📂 Project Structure

```
app/
components/
hooks/
lib/
backend/
public/
```

---

## 🚀 Getting Started

### Clone the repository

```bash
git clone https://github.com/SamRepository25/WebShield.git
cd WebShield
```

### Install dependencies

```bash
npm install
```

### Run development server

```bash
npm run dev
```

Open:

```text
http://localhost:3000
```

---

## 📦 Build

```bash
npm run build
```

Start production server:

```bash
npm start
```

The production start command enables the SSRF egress guard automatically.

---

## 🎯 What WebShield Checks

- HTTPS Availability
- TLS certificate information
- Security Headers
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
  - Permissions-Policy
- Cookie security
- Redirect chain
- Server information exposure
- Overall Security Score
- Security Recommendations
- Raw Response Headers

---

## 📸 Screenshots

Added screenshots inside:

```text
docs/
```

Example:

```text
docs/home.png
docs/results.png
```

---

## 📌 Roadmap

- Advanced TLS Analysis
- Security History Improvements
- API Improvements
- Expanded security checks

---

## 🤝 Contributing

Contributions, suggestions, and bug reports are welcome.

Feel free to open an issue or submit a pull request.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## 👨‍💻 Author

**B SIMAK AHMED**

GitHub:
https://github.com/SamRepository25
