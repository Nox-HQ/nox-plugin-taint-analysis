const { exec } = require('child_process');

function handleRequest(req, res) {
    const cmd = req.query.cmd;
    runCommand(cmd);
}

function runCommand(userCmd) {
    child_process.exec(userCmd);
}

function safeHandler(req, res) {
    const data = "static";
    processData(data);
}

function processData(value) {
    console.log(value);
}
