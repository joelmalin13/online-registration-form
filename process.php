<?php
/**
 * VTU Web Technology Lab - Assignment 2
 * Registration Form Processing & Display Handler
 *
 * Requirements:
 * - Only accept HTTP POST requests; redirect direct GET requests to index.html.
 * - Server-side validation for all fields.
 * - Complete output sanitization using htmlspecialchars() to prevent XSS.
 * - Clean semantic HTML layout matching index.html with shared stylesheet.
 * - Strictly NO JavaScript, NO jQuery, NO external libraries.
 */

// Set default timezone to Asia/Kolkata (IST)
date_default_timezone_set('Asia/Kolkata');

// -----------------------------------------------------------------------------
// 1. HTTP METHOD CHECK
// -----------------------------------------------------------------------------
// If this file is accessed directly via GET or any method other than POST, redirect.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.html');
    exit;
}

// -----------------------------------------------------------------------------
// 2. HELPER FUNCTIONS
// -----------------------------------------------------------------------------
/**
 * Safely escape any string for output in HTML context.
 *
 * @param string $data
 * @return string
 */
function sanitize(string $data): string {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

// -----------------------------------------------------------------------------
// 3. RETRIEVE AND TRIM FORM DATA
// -----------------------------------------------------------------------------
$fullname  = trim($_POST['fullname'] ?? '');
// Convert email to lowercase before validating and displaying
$email     = strtolower(trim($_POST['email'] ?? ''));
$phone     = trim($_POST['phone'] ?? '');
$dob       = trim($_POST['dob'] ?? '');
$gender    = trim($_POST['gender'] ?? '');
$branch    = trim($_POST['branch'] ?? '');
$year      = trim($_POST['year'] ?? '');
$address   = trim($_POST['address'] ?? '');
$terms     = trim($_POST['terms'] ?? '');
$rawInterests = isset($_POST['interests']) && is_array($_POST['interests']) ? $_POST['interests'] : [];

// -----------------------------------------------------------------------------
// 4. WHITELISTS FOR CONTROLLED INPUTS
// -----------------------------------------------------------------------------
$allowedGenders = ['Male', 'Female', 'Other'];

$allowedBranches = [
    'Computer Science',
    'Information Science',
    'Electronics',
    'Mechanical',
    'Civil'
];

$allowedYears = ['1st', '2nd', '3rd', '4th'];

$allowedInterests = [
    'Web Development',
    'Cybersecurity',
    'Programming',
    'Design'
];

// Allowed TLDs to prevent common typos
$allowedTlds = ['com', 'in', 'org', 'net', 'edu', 'ac.in', 'edu.in', 'co.in', 'gov.in', 'io', 'co'];

// -----------------------------------------------------------------------------
// 5. SERVER-SIDE VALIDATION
// -----------------------------------------------------------------------------
$errors = [];

// 1. Full Name: letters, spaces, dots, apostrophes and hyphens only (length 3-50, no digits)
$nameLen = mb_strlen($fullname);
if ($fullname === '' || $nameLen < 3 || $nameLen > 50 || !preg_match('/^[A-Za-z][A-Za-z .\'\-]{2,49}$/u', $fullname) || preg_match('/\d/', $fullname)) {
    $errors['Full Name'] = 'Name must contain letters only.';
}

// 2. Email Address: valid format, allowed TLD, and DNS MX check
$emailValid = true;
if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $emailValid = false;
} else {
    $domain = substr(strrchr($email, '@'), 1);
    // Require domain to end with a real TLD of at least 2 letters
    if (!preg_match('/\.[a-z]{2,}$/', $domain)) {
        $emailValid = false;
    } else {
        // Check domain ending against allowed list of TLDs
        $hasAllowedTld = false;
        foreach ($allowedTlds as $tld) {
            $suffix = '.' . $tld;
            if (str_ends_with($domain, $suffix) && strlen($domain) > strlen($suffix)) {
                $hasAllowedTld = true;
                break;
            }
        }

        if (!$hasAllowedTld) {
            $emailValid = false;
        } else {
            // Confirm domain can receive mail via checkdnsrr; skip if DNS check is unavailable or fails
            if (function_exists('checkdnsrr')) {
                $dnsOperational = @checkdnsrr('google.com', 'MX');
                if ($dnsOperational) {
                    if (!@checkdnsrr($domain, 'MX')) {
                        $emailValid = false;
                    }
                }
            }
        }
    }
}

if (!$emailValid) {
    $errors['Email Address'] = 'Enter a valid email address (for example, name@gmail.com).';
}

// 3. Phone Number: required, exactly 10 digits
if ($phone === '' || !preg_match('/^[0-9]{10}$/', $phone)) {
    $errors['Phone Number'] = 'Phone number must contain exactly 10 numeric digits.';
}

// 4. Date of Birth: valid calendar date, not in the future, student between 16 and 60 years old
$dobFormatted = '';
if ($dob === '') {
    $errors['Date of Birth'] = 'Date of birth is required.';
} else {
    $dobDate = DateTime::createFromFormat('Y-m-d', $dob);
    $dateErrors = DateTime::getLastErrors();
    $warningCount = $dateErrors['warning_count'] ?? 0;
    $errorCount   = $dateErrors['error_count'] ?? 0;

    if (!$dobDate || $warningCount > 0 || $errorCount > 0) {
        $errors['Date of Birth'] = 'Date of birth must be a valid date in YYYY-MM-DD format.';
    } else {
        $dobDate->setTime(0, 0, 0);
        $today = new DateTime('today');
        if ($dobDate > $today) {
            $errors['Date of Birth'] = 'Date of birth cannot be in the future.';
        } else {
            $age = $dobDate->diff($today)->y;
            if ($age < 16) {
                $errors['Date of Birth'] = 'You must be at least 16 years old to register.';
            } elseif ($age > 60) {
                $errors['Date of Birth'] = 'You must be at least 16 years old and not older than 60.';
            } else {
                // Consistent date format: "3 November 2026"
                $dobFormatted = $dobDate->format('j F Y');
            }
        }
    }
}

// 5. Gender: required, must match allowed values
if ($gender === '' || !in_array($gender, $allowedGenders, true)) {
    $errors['Gender'] = 'Invalid gender value selected.';
}

// 6. Course / Branch: required, must match allowed values
if ($branch === '' || !in_array($branch, $allowedBranches, true)) {
    $errors['Course / Branch'] = 'Invalid course / branch selection.';
}

// 7. Year of Study: required, must match allowed values
if ($year === '' || !in_array($year, $allowedYears, true)) {
    $errors['Year of Study'] = 'Invalid year of study selection.';
}

// 8. Technical Interests: optional, but all items must be in whitelist
$validInterests = [];
foreach ($rawInterests as $interest) {
    if (in_array($interest, $allowedInterests, true)) {
        $validInterests[] = $interest;
    } else {
        $errors['Interests'] = 'Invalid interest selection detected.';
        break;
    }
}

// 9. Address: min 10 characters, max 200 characters, must contain at least one letter
$addrLen = mb_strlen($address);
if ($address === '' || $addrLen < 10 || $addrLen > 200 || !preg_match('/[a-zA-Z]/', $address)) {
    $errors['Address'] = 'Address must be at least 10 characters.';
}

// 10. Terms & Conditions: required checkbox
if ($terms !== 'accepted') {
    $errors['Terms & Conditions'] = 'You must agree to the terms and conditions to complete registration.';
}

// -----------------------------------------------------------------------------
// 6. DISPLAY RESULT: ERROR PAGE OR SUCCESS PAGE
// -----------------------------------------------------------------------------
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title><?php echo empty($errors) ? 'Registration Successful' : 'Registration Error'; ?> | VTU Web Technology Lab</title>

  <!-- Google Fonts -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">

  <!-- Shared CSS Stylesheet -->
  <link rel="stylesheet" href="css/style.css">
</head>
<body>

  <!-- Semantic Header -->
  <header id="page-header">
    <div class="container header-inner">
      <h1>VTU Web Technology Lab</h1>
      <p>Department of Computer Science &amp; Engineering | Student Portal</p>
    </div>
  </header>

  <!-- Main Content Container -->
  <main class="container">

    <?php if (!empty($errors)): ?>
      <!-- ERROR VIEW: Displayed when server-side validation detects issues -->
      <section class="card" id="error-card">
        <div class="card-header">
          <h2>Registration Failed</h2>
          <p>We could not process your submission due to the following validation errors:</p>
        </div>

        <div class="alert alert-error">
          <strong>Validation Errors Detected:</strong>
          <ul class="error-list">
            <?php foreach ($errors as $fieldName => $errorMsg): ?>
              <li><strong><?php echo sanitize($fieldName); ?>:</strong> <?php echo sanitize($errorMsg); ?></li>
            <?php endforeach; ?>
          </ul>
        </div>

        <div class="form-actions">
          <a href="index.html" class="btn btn-secondary">&larr; Return to Registration Form</a>
        </div>
      </section>

    <?php else: ?>
      <?php
        // Success Details Setup
        $refId = 'REG-' . date('Y') . '-' . str_pad((string)random_int(1000, 9999), 4, '0', STR_PAD_LEFT);
        // Time formatted with IST label: "3 November 2026, 12:19 PM IST"
        $registrationTime = date('j F Y, g:i A \I\S\T');
      ?>
      <!-- SUCCESS VIEW: Displayed when all server validations pass -->
      <section class="card" id="result-card">
        
        <!-- Success Banner -->
        <div class="alert alert-success">
          <h2>Registration Successful!</h2>
          <p>
            Congratulations, <strong><?php echo sanitize($fullname); ?></strong>! 
            Your registration details have been received successfully.
          </p>
        </div>

        <!-- Registration Metadata Box -->
        <div class="meta-box">
          <div class="meta-item">
            <span class="meta-label">Reference ID</span>
            <span class="meta-val"><?php echo sanitize($refId); ?></span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Registration Date &amp; Time</span>
            <span class="meta-val"><?php echo sanitize($registrationTime); ?></span>
          </div>
          <div class="meta-item">
            <span class="meta-label">Status</span>
            <span class="meta-val" style="color: var(--state-valid);">Submitted</span>
          </div>
        </div>

        <!-- Formatted Summary Table -->
        <div class="table-container">
          <h3>Submitted Student Details</h3>
          <table>
            <tbody>
              <tr>
                <th scope="row">Full Name</th>
                <td><?php echo sanitize($fullname); ?></td>
              </tr>
              <tr>
                <th scope="row">Email Address</th>
                <td><?php echo sanitize($email); ?></td>
              </tr>
              <tr>
                <th scope="row">Phone Number</th>
                <td><?php echo sanitize($phone); ?></td>
              </tr>
              <tr>
                <th scope="row">Date of Birth</th>
                <td><?php echo sanitize($dobFormatted); ?></td>
              </tr>
              <tr>
                <th scope="row">Gender</th>
                <td><?php echo sanitize($gender); ?></td>
              </tr>
              <tr>
                <th scope="row">Course / Branch</th>
                <td><?php echo sanitize($branch); ?></td>
              </tr>
              <tr>
                <th scope="row">Year of Study</th>
                <td><?php echo sanitize($year); ?> Year</td>
              </tr>
              <tr>
                <th scope="row">Specialization Interests</th>
                <td>
                  <?php if (!empty($validInterests)): ?>
                    <div class="badge-container">
                      <?php foreach ($validInterests as $interest): ?>
                        <span class="badge"><?php echo sanitize($interest); ?></span>
                      <?php endforeach; ?>
                    </div>
                  <?php else: ?>
                    <em>No specific interests selected</em>
                  <?php endif; ?>
                </td>
              </tr>
              <tr>
                <th scope="row">Residential Address</th>
                <td><?php echo nl2br(sanitize($address)); ?></td>
              </tr>
              <tr>
                <th scope="row">Terms &amp; Conditions</th>
                <td>Accepted on <?php echo date('j F Y'); ?></td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Action Controls -->
        <div class="form-actions">
          <a href="index.html" class="btn btn-primary">Register Another Student</a>
        </div>

        <!-- Print Guidance Note (No JavaScript) -->
        <p class="print-note">
          Tip: Press <strong>Ctrl + P</strong> (or <strong>Cmd + P</strong> on Mac) to print or save this confirmation as a PDF.
        </p>
      </section>

    <?php endif; ?>

  </main>

  <!-- Semantic Footer -->
  <footer>
    <p>&copy; 2026 VTU Web Technology Lab. All rights reserved.</p>
  </footer>

</body>
</html>
