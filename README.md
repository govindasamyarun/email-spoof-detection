# Email Spoof Detection #
=====

An email parser is a software or tool used for data extraction from incoming emails used to automate workflow. Processing sensitive information using email parsers is riskier without implementing proper security controls. Threat actors could use legitimate domain and display name spoofing techniques to trick the parsers into processing fraudulent emails. 

Real-time email header analysis is essential to prevent spoofing attacks. This module will help perform email header analysis. 

# Installation

```bash
$ npm i email-spoof-detection
```

## Node.js JavaScript

Refer example.js

```js
var analysis = require('email-spoof-detection');

var header = "email-header";
var emailDomain = "test.com";

var output = analysis.emailSpoofDetection(header, emailDomain);

// { validEmail: true }
// { validEmail: false }

```
