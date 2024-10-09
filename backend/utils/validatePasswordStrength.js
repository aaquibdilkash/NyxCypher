function validatePasswordStrength(password) {
  // Define the password strength requirements
  const MIN_LENGTH = 8;
  const MAX_LENGTH = 32;
  const REQUIREMENTS = [
    { type: "lowercase", regex: /[a-z]/ },
    { type: "uppercase", regex: /[A-Z]/ },
    { type: "number", regex: /\d/ },
    { type: "specialChar", regex: /[!@#$%^&*()_+\-=\[\]{}|;':"\\/,.<>?]/ },
    { type: "nonSpaceChar", regex: /\S/ },
  ];

  // Check password length
  if (password.length < MIN_LENGTH || password.length > MAX_LENGTH) {
    return false;
  }

  // Check each requirement
  for (let i = 0; i < REQUIREMENTS.length; i++) {
    if (!REQUIREMENTS[i].regex.test(password)) {
      return false;
    }
  }

  // All checks passed
  return true;
}

module.exports = { validatePasswordStrength };
