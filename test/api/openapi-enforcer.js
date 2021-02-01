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
