var cluster = require('cluster');
var fs = require('fs');
var express = require('express');
var app = express();
var fs = require('fs');
var bodyParser = require('body-parser');  
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

//This next line sets the server info
var logging = false;                
//var dbhost = 'localhost';
//var dbuser = 'root';
//var dbpass = 'root';
var SSL = false;                    
var httpport = 8080;
var httpsport = 4433;

if (SSL) {
    var privateKey  = fs.readFileSync('./certs/cert-name.key', 'utf8');
    var certificate = fs.readFileSync('./certs/cert-name.crt', 'utf8');
    var credentials = { key: privateKey, cert: certificate };
    var https = require('https');
    var httpsServer = https.createServer(credentials, app);
} else {
    var http = require('http');
    var httpServer = http.createServer(app);
}

// Code to run if we're in the master process
if (cluster.isMaster) {


    // Count the machine's CPUs
    var cpuCount = require('os').cpus().length;


    // Create a worker for each CPU
    for (var i = 0; i < cpuCount; i += 1) {
        cluster.fork();
    }


// Code to run if we're in a worker process
} else {
    try {

// --------------- Main Functions --------------- //
        function routeLogger(req){
            try {
                var date = new Date();
                var ipaddr = req.connection.remoteAddress;
                var fullUrl = req.protocol + '://' + req.get('host') + req.originalUrl;
                var line = (date + '').replace(/\(.+?\)/g,'') + ipaddr + ' ' + fullUrl.replace(/https?\:\/\/.+?\//g, '') + " " + JSON.stringify(req.body);
                console.log(line); 
                return;
            } catch (err) {
                console.log(err);
            }
        }

// --------------- Beginning of Routes --------------- //
        // Add a basic route – index page
        app.get(['/','index.html'], function (req, res) {
            routeLogger(req);
            res.sendFile('pub/html/index.html', {root: __dirname});
        });

        app.get(['/static.js'], function (req, res) {
            routeLogger(req);
            if (req.query.file) {
                var thefile = req.query.file.replace(/\.\./g,'');
                fs.access('./pub/' + thefile, fs.F_OK, function(err) { 
                    if (!err) {
                        res.sendFile('pub/'+thefile, {root: __dirname});
                    } else {
                        res.send('404 not found');
                    }
                });
            } else {
                res.send('404 not found')
            }
        });


        // Bind to a port
        console.log('[+] Worker '+cluster.worker.id+' running');
        if (SSL) {
            httpsServer.listen(httpsport)
        } else {
            httpServer.listen(httpport);
        }
    } catch (err) {
        console.log(err.message)
    }


}
