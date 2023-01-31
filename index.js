exports.emailSpoofDetection = function(header, emailDomain){

    // Assign header and emailDomain to a variable 
    var header = JSON.stringify(header);
    var emailDomain = emailDomain;

    // Convert Gmail header object format to raw string 
    header = header.replace(/\{\"name\"\:\"/g, '');
    header = header.replace(/\"\,\"value\"\:\"/g, ': ');
    header = header.replace(/\"\}\,/g, ', ');
    header = header.replace(/^\[/g, '');
    header = header.replace(/\"\}\]$/g, '');

    // Remove new line characters, if any 
    header = header.replace(/\\n/g, ' ');
    header = header.replace(/\s+/g, ' ');
    header = header.replace(/\\t/g, ' ');

    var match = [];
    var outcome = {};

    // Parse dkmin records in the header 
    const dkimRegex = /dkim\=(\S+)\sheader\.i\=\@(\S+)\s/g;
    const dkim = {"result": [], "domain": []}
    while((match = dkimRegex.exec(header)) !== null){
    if (!dkim["result"].includes("pass")){
            dkim["result"].push(match[1]);
    }
    if (!dkim["domain"].includes(match[2])){
            dkim["domain"].push(match[2]);
        }
    }

    // Parse spf records in the header 
    const spfRegex = /spf\=(\S+).*?smtp\.mailfrom\=.*?\@(.*?)\;\s/g;
    const spf = {"result": [], "domain": []}
    while((match = spfRegex.exec(header)) !== null){
        if (!spf["result"].includes("pass")){
            spf["result"].push(match[1]);
    }
    if (!spf["domain"].includes(match[2])){
            spf["domain"].push(match[2]);
        }
    }

    // Parse dmarc records in the header 
    const dmarcRegex = /dmarc\=(\S+)\s\(p\=\S+\s+sp\=\S+\s+dis\=\S+\)\s+header\.from\=(\S+)/g;
    const dmarc = {"result": [], "domain": []}
    while((match = dmarcRegex.exec(header)) !== null){
        if (!dmarc["result"].includes("pass")){
            dmarc["result"].push(match[1]);
    }
    if (!dmarc["domain"].includes(match[2])){
            dmarc["domain"].push(match[2]);
        }
    }

    // Validate the result and domain name 
    if (dkim["result"].includes("pass") && spf["result"].includes("pass") && dmarc["result"].includes("pass") && dkim["domain"].includes(emailDomain)) {
        outcome = {'validEmail': true};
    } else {
        outcome = {'validEmail': false};
    }
    return outcome;
};