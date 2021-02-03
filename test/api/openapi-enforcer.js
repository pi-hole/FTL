// Pi-hole: A black hole for Internet advertisements
// (c) 2021 Pi-hole, LLC (https://pi-hole.net)
// Network-wide ad blocking via your own hardware.
//
// FTL - API test file
//
// This is a node script
//
// This file is copyright under the latest version of the EUPL.
// Please see LICENSE file for your rights under this license.

const Enforcer = require('openapi-enforcer');

// JSON and YAML files accepted
Enforcer('src/api/docs/content/specs/main.yaml', { fullResult: true })
    .then(function ({ error, warning }) {
        if (!error && !warning) {
            console.log('No errors with your document')
        } else {
            if(error) console.error(error)
            if(warning) console.warn(warning);
            process.exit(1);
        }
    })
