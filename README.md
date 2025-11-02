# Bug Report - D.Watson Pharmacy Dashboard

**Generated:** 2025-01-27  
**Project:** D.Watson Pharmacy Sales Dashboard  
**Severity:** Multiple issues ranging from Critical to Low

---

## Critical Bugs 🔴

### 1. **Incorrect `.env` File Path Configuration**
**File:** `server/index.js`  
**Line:** 14  
**Severity:** 🔴 CRITICAL  
**Status:** ⚠️ UNFIXED

**Description:**
The `dotenv.config()` is called without specifying the path to the `.env` file. Since the server runs from the root directory (`node server/index.js`), but the `.env` file is in the `server/` subdirectory, the environment variables are not being loaded correctly.

**Current Code:**
```javascript
dotenv.config(); // ❌ Will look for .env in current working directory
```

**Expected Behavior:**
The `.env` file in the `server/` directory should be loaded when starting the application.

**Impact:**
- All environment variables fail to load in production
- Server cannot connect to MongoDB
- JWT authentication fails
- Admin password checks fail
- Application crashes on startup

**Location:**
- Line 14 in `server/index.js`

**Reproduction:**
1. Start server with `npm start` or `node server/index.js`
2. Check console for environment variable errors
3. Server fails to read `MONGODB_URI`, `JWT_SECRET`, etc.

---

### 2. **Inconsistent Environment Variable Fallback**
**File:** `server/index.js`  
**Lines:** 377  
**Severity:** 🔴 CRITICAL  
**Status:** ⚠️ UNFIXED

**Description:**
The JWT_SECRET has a weak fallback default value that is the same across all deployments. This creates a security vulnerability where any deployment without the environment variable uses the same secret, allowing token forgery.

**Current Code:**
```javascript
const JWT_SECRET = process.env.JWT_SECRET || 'pharmacy_sales_secret_key';
```

**Expected Behavior:**
The application should exit with an error if JWT_SECRET is not set in production environments.

**Impact:**
- Security vulnerability: all deployments share same JWT secret
- Tokens can be forged from one deployment to another
- Authentication bypass potential

**Location:**
- Line 377 in `server/index.js`

---

### 3. **Hardcoded Fallback Admin Password**
**File:** `server/index.js`  
**Line:** 514  
**Severity:** 🔴 CRITICAL  
**Status:** ⚠️ UNFIXED

**Description:**
The admin password has a hardcoded fallback value that is publicly documented in the README. This creates a serious security vulnerability.

**Current Code:**
```javascript
const expectedPassword = process.env.ADMIN_PASSWORD || 'admin123';
```

**Expected Behavior:**
The application should exit with an error if ADMIN_PASSWORD is not set, especially in production.

**Impact:**
- Default admin password is 'admin123' (known publicly)
- Unauthorized users can promote themselves to admin
- Critical security breach

**Location:**
- Line 514 in `server/index.js`

**Related Documentation:**
- README.md line 51 explicitly shows `ADMIN_PASSWORD=admin123` as example

---

## High Priority Bugs 🟠

### 4. **Typo in README Filename**
**File:** `server/READEME.md`  
**Severity:** 🟠 HIGH  
**Status:** ⚠️ UNFIXED

**Description:**
The README file in the server directory is misspelled as `READEME.md` instead of `README.md`.

**Impact:**
- Inconsistent naming convention
- Difficult to find documentation
- Unprofessional appearance

**Location:**
- File: `server/READEME.md`

**Expected File Name:**
- `server/README.md`

---

### 5. **Missing .env File in Project**
**Severity:** 🟠 HIGH  
**Status:** ⚠️ NOT FOUND

**Description:**
No `.env` file exists in the `server/` directory. While `.env` files are typically gitignored, there should be a `.env.example` file to guide developers.

**Impact:**
- Developers don't know what environment variables are needed
- No template for setup
- Increased onboarding time

**Expected:**
- Create `server/.env.example` with template values

---

### 6. **Race Condition in Database Seeding**
**File:** `server/index.js`  
**Lines:** 2324-2459  
**Severity:** 🟠 MEDIUM-HIGH  
**Status:** ⚠️ UNFIXED

**Description:**
The `seedDefaultData()` function is called on MongoDB connection open (`mongoose.connection.once('open', ...)`), but if the database is already connected, the event may never fire, causing seeding to never run.

**Current Code:**
```javascript
mongoose.connection.once('open', () => {
  seedDefaultData();
});
```

**Impact:**
- Seeding may not run if database is already connected
- Missing default data in some deployment scenarios
- Inconsistent application state

**Location:**
- Lines 2534-2536 in `server/index.js`

---

## Medium Priority Bugs 🟡

### 7. **Missing Input Validation in Admin Endpoints**
**File:** `server/index.js`  
**Lines:** 2204-2258, 2261-2317  
**Severity:** 🟡 MEDIUM  
**Status:** ⚠️ UNFIXED

**Description:**
The admin delete and update endpoints (`/api/admin/delete` and `/api/admin/update`) accept `adminPassword` from the request body but don't use `checkDatabaseConnection` middleware, and have minimal input validation.

**Issues:**
1. Admin operations could proceed even with database issues
2. No rate limiting on admin endpoints
3. No logging of admin actions

**Impact:**
- Potential data loss during database issues
- No audit trail for admin actions
- Vulnerable to brute force attacks

**Location:**
- Lines 2204-2258 (delete endpoint)
- Lines 2261-2317 (update endpoint)

---

### 8. **Potential Memory Leak in Rate Limiting**
**File:** `server/index.js`  
**Lines:** 72-102  
**Severity:** 🟡 MEDIUM  
**Status:** ⚠️ UNFIXED

**Description:**
Rate limiting uses an in-memory Map that never gets cleaned up. Over time, this could grow indefinitely as new IPs connect.

**Current Code:**
```javascript
const rateLimitMap = new Map();
```

**Impact:**
- Memory usage grows over time
- Potential server crash after long uptime
- No automatic cleanup mechanism

**Location:**
- Lines 72-102 in `server/index.js`

**Expected Behavior:**
- Periodic cleanup of old entries
- Maximum map size limit
- Or use a proper rate limiting library

---

### 9. **No Session Management**
**File:** `server/index.js`  
**Severity:** 🟡 MEDIUM  
**Status:** ⚠️ UNFIXED

**Description:**
JWT tokens are issued but there's no logout mechanism that invalidates tokens. Tokens remain valid until expiration even after logout.

**Current Implementation:**
```javascript
app.post('/api/auth/logout', authenticate, (req, res) => {
  res.json({ message: 'Logged out successfully' });
});
```

**Impact:**
- Logout doesn't actually invalidate tokens
- Stolen tokens remain valid until expiration
- Security concern for compromised accounts

**Location:**
- Lines 677-679 in `server/index.js`

---

### 10. **Case-Sensitive Duplicate Check Mismatch**
**File:** `server/index.js`  
**Lines:** 874, 908-915  
**Severity:** 🟡 MEDIUM  
**Status:** ⚠️ UNFIXED

**Description:**
Branch creation uses case-insensitive duplicate checks, but update only checks if the name changed before enforcing uniqueness. This could allow case-only duplicates during updates.

**Current Code (Create):**
```javascript
const exists = await Branch.findOne({ name: { $regex: `^${name}$`, $options: 'i' } });
```

**Current Code (Update):**
```javascript
const currentName = String(current.name || '').toLowerCase().trim();
const newName = payload.name.toLowerCase().trim();
const nameChanged = currentName !== newName;
// Only checks if name changed
```

**Impact:**
- Potential duplicate branch names differing only by case
- Data inconsistency
- User confusion

**Location:**
- Lines 874-876 (create)
- Lines 908-915 (update)

---

### 11. **Redundant User Fetch in Login**
**File:** `server/index.js`  
**Lines:** 651-654  
**Severity:** 🟡 LOW  
**Status:** ⚠️ UNFIXED

**Description:**
After saving `user.lastLogin`, the code immediately fetches the user again unnecessarily.

**Current Code:**
```javascript
user.lastLogin = new Date();
await user.save();

// Unnecessary fetch
const updatedUser = await User.findById(user._id).populate('groupId');

const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1d' });

res.json({
  token,
  user: {
    id: updatedUser._id,  // Could use user._id
    // ...
  }
});
```

**Impact:**
- Unnecessary database query
- Minor performance impact

**Location:**
- Lines 651-669 in `server/index.js`

---

## Low Priority Bugs / Code Quality Issues 🟢

### 12. **Inconsistent Error Messages**
**File:** `server/index.js`  
**Lines:** 635-640  
**Severity:** 🟢 LOW  
**Status:** ⚠️ UNFIXED

**Description:**
Login returns generic "Invalid credentials" for both user not found and inactive user scenarios. This reduces security by providing less information than needed.

**Impact:**
- Harder to debug authentication issues
- Slight security concern (information disclosure)

**Location:**
- Lines 635-640 in `server/index.js`

---

### 13. **Empty Production JWT Secret Validation**
**File:** `server/index.js`  
**Lines:** 379-380  
**Severity:** 🟢 LOW  
**Status:** ⚠️ UNFIXED

**Description:**
Comment says "JWT secret validation for production" but there's no actual validation code.

**Current Code:**
```javascript
// JWT secret validation for production


```

**Impact:**
- Incomplete implementation
- Confusing code

**Location:**
- Lines 379-380 in `server/index.js`

---

### 14. **No Production Environment Validation**
**File:** `server/index.js`  
**Severity:** 🟢 LOW  
**Status:** ⚠️ UNFIXED

**Description:**
The application doesn't validate that required environment variables are set when in production mode.

**Expected Behavior:**
Should validate all required variables at startup and exit if missing in production.

---

## Configuration Issues

### 15. **Incorrect Railway Build Command**
**File:** `railway.json`  
**Line:** 5  
**Severity:** 🟡 MEDIUM  
**Status:** ⚠️ UNFIXED

**Description:**
The build command runs `npm install` in the server directory, but package.json might have dependencies at the root level too.

**Current:**
```json
{
  "build": {
    "builder": "NIXPACKS",
    "buildCommand": "cd server && npm install"
  }
}
```

**Potential Issue:**
- Root dependencies might not be installed
- Could cause deployment failures

---

### 16. **Missing Dev Dependencies**
**Severity:** 🟢 LOW  
**Status:** ⚠️ UNFIXED

**Description:**
No devDependencies section in package.json files. Missing testing, linting, and development tools.

**Expected:**
- Testing framework (Jest/Mocha)
- Linter (ESLint)
- Code formatter (Prettier)
- Development documentation tools

---

## Summary

**Total Bugs Found:** 16  
**Critical:** 3 🔴  
**High:** 3 🟠  
**Medium:** 5 🟡  
**Low:** 5 🟢  

### Priority Action Items:
1. **FIX IMMEDIATELY:**
   - Fix `.env` file path loading
   - Remove hardcoded security defaults
   - Validate environment variables in production

2. **FIX SOON:**
   - Fix README typo
   - Add `.env.example` file
   - Fix database seeding race condition

3. **IMPROVE:**
   - Add proper logging and monitoring
   - Implement token blacklist for logout
   - Add input validation
   - Fix memory leaks

4. **CLEAN UP:**
   - Remove duplicate user fetch
   - Complete JWT validation
   - Add proper error handling
   - Add development dependencies

---

**Report Generated By:** AI Code Analysis  
**Date:** 2025-01-27  
**Tools Used:** Static code analysis, pattern matching, configuration review

