var output = [];
var globalPAT = [];
var ACLs = {};
var aclCounter = 1;

$(document).ready(function() {
    $("#convertit").click(function(){
        // clear the output area
        document.convert.nat84.value = "";

        // put the form data into a variable
        var input = document.convert.nat82.value;

            // remove double spaces
        input = input.replace("  ", " ");
            // remove trailing and leading spaces (basically doing a trim)
        input = input.replace(/(^\s*)|(\s*$)/gi,"");
        input = input.replace(/[ ]{2,}/gi," ");
        input = input.replace(/\n /,"\n");

        output = [];
        globalPAT = [];
        ACLs = {};

        var eachLine = input.split('\n');
        
        // iterate over every line and grab any globals or ACLs we find and put them in a special array
        for (var i=0; i < eachLine.length; i++) {
            var invalid = 0;
            var line1 = eachLine[i];
            var token = line1.split(' ');
            if (token[0] == "global") {
                processGlobal(token, line1);
            } else if (token[0] == "access-list") {
                processACL(token, line1);
            }
        }
        output.push(""); // new line between ACLs and other NAT statement
        
        var skipped = [];
        // iterate over each line entered and send line to proper function to be processed
        for (var i=0; i < eachLine.length; i++) {
            var line1 = eachLine[i];
            if (line1 == "") {
                    continue;
            }
            // tokenize each line of the input
            // 0           1                  2          3            4                  5               6             7    8
            // static      (Inside,Outside)   55.55.55.2 192.168.1.2  netmask            255.255.255.255 
            // access-list ACL-VENDOR-VPN-NAT extended   permit       ip                 192.168.1.0     255.255.255.0 host 172.16.75.5
            // nat         (inside)           3          access-list  ACL-VENDOR-VPN-NAT
            // global      (outside)          3          172.27.27.27 
            // nat         (inside)           1          10.0.0.0     255.255.255.0
            // global      (outside)          1          interface
            var token = line1.split(' ');

            //conduct form validation & process line accordingtly
            if (token[0] == "static") {
                output.push("! Original statement: " + line1);
                processStatic(token);
            } else if (token[0] == "nat") {
                output.push("! Original statement: " + line1);
                processPAT(token);
            } else if (token[0] == "global") {
                // placeholder
            } else if (token[0] == "access-list") {
                // placeholder
            } else {
                skipped.push(line1);
            }

        }
        if (skipped.length > 0) {
                output.push("! Warning: Skipped the following lines because they aren't related to the NAT configuration.");
                for (var i = 0; i < skipped.length; i++) {
                    output.push("! " + skipped[i]);
                }
                output.push("");
        } 
     
        _gaq.push(['_trackEvent', 'NAT Converter', 'Convert', 'Clicked',, false]);

        // Places the output into the textarea
        for (var i=0; i < output.length; i++) {
            document.convert.nat84.value = document.convert.nat84.value + "\n" + output[i];
        }
    });

    function processPAT(token) {
        // 0           1                  2          3            4                   5
        // nat         (inside)           3          access-list  ACL-VENDOR-VPN-NAT
        // nat         (inside)           1          10.0.0.0     255.255.255.0       dns

        // intended results: nat (token2,globalpatINT) source dynamic OBJ-token3 OBJ-globalPatIP
        var foundGlobal = false;
        var invalid = 0;

        // Strip off "(" and ")" from interface
        var natInterface = token[1].replace(/\(/,"");
        natInterface = natInterface.replace(/\)/,"");

        // examples:
        // globalPAT[0] = ["1", "OUTSIDE", "22.22.22.22"]
        // globalPAT[1] = ["1", "DMZ", "11.11.11.11"]
        // loop through all of the globalPATs that were extracted earlier
        for (var k in globalPAT) {
            // use hasOwnProperty to filter out keys from the Object.prototype
            // if (globalPAT.hasOwnProperty(k)) {
                //console.log('nat group is: ' + globalPAT[k][0] + ', interface is ' + globalPAT[k][1] + ', pat ip is ' + globalPAT[k][2]);

                if (globalPAT[k][0] == token[2]) {
                    foundGlobal = true;
                    var mappedIP = globalPAT[k][2];
                    // var obj2 = "OBJ-" + mappedIP;
                    // // Create global PAT IP object
                    // if (mappedIP == "interface") {
                    //     obj2 = "interface";
                    // } 
                    var obj2 = globalPAT[k][3];

                    if (token[3] == "access-list") {
                        var ACLname = token[4];
                        createNATfromACL(ACLname, natInterface, globalPAT[k][1], obj2, "after-auto", "PAT");
                        // output.push("! Error: Access-list support is not available at this time.\n");
                    } else {
                        var realIP = token[3];
                        var realIPNetmask = token[4];
                        var obj1 = "OBJ-" + realIP;
                        var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
                        var ipArray = realIP.match(ipPattern);
                        if ( (ipArray == null) && (realIP != "interface") ) {
                            output.push("! Error, invalid IP address in statement.");
                            return;
                        }
                        output.push("! Using: global ("+globalPAT[k][1]+") " + globalPAT[k][0] + " " +    globalPAT[k][2]);


                        // Create object for traffic to be NAT'd
                        if (realIPNetmask == "255.255.255.255") {
                            output.push("object network " + obj1);
                            output.push("  host " + realIP);                          
                        } else if (realIP == "0.0.0.0") {
                            obj1 = "any";
                        } else {
                            var cidr = convertNetmaskToCIDR(realIPNetmask);
                            obj1 = obj1 + "-" + cidr;
                            output.push("object network " + obj1);
                            output.push("  subnet " + realIP + " " + realIPNetmask);
                            // FIX: name of a subnet object group should indicate how many bits long it is
                        }
                        if (token[5] != undefined) {
                            if (token[5] == "dns") {
                                var dns = token[5];
                            } else {
                                var dns = "";
                            }
                        } else {
                            var dns = "";
                        }
                        output.push("nat (" + natInterface + "," + globalPAT[k][1] + ") after-auto source dynamic " + obj1 + " " + obj2 + " "+dns+" description PAT");

                        output.push("");
                    }
                }
            // }
        }

        if (token[2] == "0") { // NAT Zero
            if (token[3] == "access-list") {
                var ACLname = token[4];
                // process a Nat Zero that has an ACL
                // nat (inside) 0 access-list acl-nonat
                createNATfromACL(ACLname, natInterface, "any", "", "1", "NONAT");


            } else {
                var mappedIP = token[3];
                var realIP = token[3];
                var realIPNetmask = token[4];
                var obj1 = "OBJ-" + realIP;
                var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
                var ipArray = mappedIP.match(ipPattern);

                if ( (ipArray == null) && (mappedIP != "interface") ) {
                    output.push("! Error, invalid IP address in statement.");
                    return;
                }

                // Create object for traffic to be NAT'd
                if (realIPNetmask == "255.255.255.255") {
                    output.push("object network " + obj1);
                    output.push("  host " + realIP);                          
                } else if (realIP == "0.0.0.0") {
                    obj1 = "any";
                } else {
                    var cidr = convertNetmaskToCIDR(realIPNetmask);
                    obj1 = obj1 + "-" + cidr;
                    output.push("object network " + obj1);
                    output.push("  subnet " + realIP + " " + realIPNetmask);
                    // FIX: name of a subnet object group should indicate how many bits long it is
                }

                output.push("nat (" + natInterface + ",any) 1 source static " + obj1 + " " + obj1 + " no-proxy-arp description NONAT");
                output.push("! Warning: Using 'any' as destination interface may be dangerous. Find real destination by looking at routes.");

                output.push("");
            }

        }



        if ( (foundGlobal == false) && (token[2] != "0") )  {
            output.push("! Warning: No matching global group found.\n");
        }
    }

    function createNATfromACL(ACLname, realInt, mappedInt, globalOBJ, loc, desc) {
                if (!ACLs.hasOwnProperty(ACLname)) {  
                    output.push("! Error: Matching ACL not found, please include it in the input.\n");
                    return;
                }

                // loop through all lines of the matching ACL
                for (var k=0; k < ACLs[ACLname].length; k++) {
                    // access-list['name'][0] = ["permit", "ip", "192.168.1.0", "255.255.255.0", "host",         "172.16.75.5"]
                    // access-list['name'][1] = ["permit", "ip", "any",         "",              "object-group", "CGINET"     ]    

                    var srcIP = ACLs[ACLname][k][2];
                    var srcMask = ACLs[ACLname][k][3];
                    var dstIP = ACLs[ACLname][k][4];
                    var dstMask = ACLs[ACLname][k][5];
                    output.push("! Using ACL " + ACLname + " line: " + ACLs[ACLname][k][0] + " " + ACLs[ACLname][k][1] + " " + ACLs[ACLname][k][2] + " " + ACLs[ACLname][k][3] + " " + ACLs[ACLname][k][4] + " " + ACLs[ACLname][k][5]);

                    if (srcIP == "any") {
                        var obj1 = "any";
                    } else if (srcIP == "object-group") {
                        var obj1 = ACLs[ACLname][k][3];
                    } else if (srcIP == "interface") {
                        var obj1 = "interface";
                    } else {
                        var cidr = convertNetmaskToCIDR(srcMask);
                        var obj1 = "OBJ-" + srcIP;
                        if (cidr != 32) {   
                            obj1 = obj1 + "-" + cidr;
                        }
                        output.push("object network " + obj1);
                        output.push("  subnet " + srcIP + " " + srcMask);                       
                    }

                    if (dstIP == "any") {
                        var obj2 = "any";
                    } else if (dstIP == "object-group") {
                        var obj2 = ACLs[ACLname][k][5];
                    } else if (srcIP == "interface") {
                        var obj2 = "interface";
                    } else {
                        var cidr = convertNetmaskToCIDR(dstMask);
                        var obj2 = "OBJ-" + dstIP;
                        if (cidr != 32) {   
                            obj2 = obj2 + "-" + cidr;
                        }
                        output.push("object network " + obj2);
                        output.push("  subnet " + dstIP + " " + dstMask);                       
                    }
                    if (globalOBJ == "") {
                        objSrcNat = obj1;
                    } else {
                        objSrcNat = globalOBJ;
                    }
                    if (desc == "NONAT") {
                        desc = " no-proxy-arp description NONAT";
                    } else if (desc == "PAT") {
                        desc = " description PAT";
                    }
                    var natType = "static ";
                    if (loc == "after-auto") {
                        natType = "dynamic ";
                    }


                    if (obj2 == "any") {
                        output.push("nat (" + realInt + "," + mappedInt + ") " + loc + " source " + natType + obj1 + " " + objSrcNat + desc);
                    } else {
                        output.push("nat (" + realInt + "," + mappedInt + ") " + loc + " source " + natType + obj1 + " " + objSrcNat + " destination static " + obj2 + " " + obj2 + desc);                        
                    }
                    if (mappedInt == "any") {
                        output.push("! Warning: Using 'any' as destination interface may be dangerous. Find real destination by looking at routes.");
                    }

                    output.push("");
                } // end for loop through each ACL line
    }

    function processACL(token, line1) {
        // 0           1                  2          3            4         5               6               7              8
        // access-list ACL-VENDOR-VPN-NAT extended   permit       ip        192.168.1.0     255.255.255.0   host           172.16.75.5
        // access-list no-nat-CGINet-acl  permit     ip        object-group PHX-CorpBNET    object-group    CGINET
        // access-list acl-nonat          extended   permit       ip        any             host            192.168.1.1    
        // access-list ACL-STANDARD       standard   permit       host      10.1.1.1    

        // access-list['name'][0] = ["permit", "ip", "192.168.1.0", "255.255.255.0", "host",         "172.16.75.5"]
        // access-list['name'][1] = ["permit", "ip", "any",         "",              "object-group", "CGINET"     ]  
        if (token[2] == "remark") {
            return;
        }  
        output.push("! Processing ACL: " + line1);

        if (token[2] == "standard") {
            // process standard acl
            var dstACLmask = token[5];
            var dstACLIP = token[4];
            if (token.hasOwnProperty(4)) {
                dstACLIP = token[4];
            }
            if (token.hasOwnProperty(5)) {
                dstACLmask = token[5];
            }
            token[4] = "ip";
            token[5] = "any";
            token[6] = dstACLIP;
            token[7] = dstACLmask;
        } else if ((token[2] == "permit") || (token[2] == "deny")) {
            // process acl that doesn't say extended
            var oldtoken = token;
            if (oldtoken.hasOwnProperty(7)) {
                token[8] = oldtoken[7];
            }
            if (oldtoken.hasOwnProperty(6)) {
                token[7] = oldtoken[6];
            }
            token[6] = oldtoken[5];
            token[5] = oldtoken[4];
            token[4] = oldtoken[3];
            token[3] = oldtoken[2];
            token[2] = "extended";
        } else if (token[2] == "extended") {
            // placeholder 
        } else {
            output.push("! Error: Access-lists does not appear to be formatted correctly.");
            return;
        }
        if (token[4] != "ip") {
            output.push("! Error: ACLs with ports in them are not yet implemented.");
            return;
        }
        if (token[3] == "deny") {
            output.push("! Warning: Unable to process ACL with deny statements.");
            return;
        }

        // Assign srcIP and destIP variables
        if (token[5] == "any") {
            var srcIP = "any";
            var srcMask = "";

            // if token5 is any then the destIPs will be moved over, so we should process them next
            if (token[6] == "any") {
                var dstIP = "any";
                var dstMask = "";
            } else if (token[6] == "host") {
                var dstIP = token[7];
                var dstMask = "255.255.255.255";
            } else {
                var dstIP = token[6];
                var dstMask = token[7];
            }

        } else if (token[5] == "host") {
            var srcIP = token[6];
            var srcMask = "255.255.255.255";
            if (token[7] == "any") {
                var dstIP = "any";
                var dstMask = "";
            } else if (token[7] == "host") {
                var dstIP = token[8];
                var dstMask = "255.255.255.255";
            } else {
                var dstIP = token[7];
                var dstMask = token[8];
            }
        } else {
            var srcIP = token[5];
            var srcMask = token[6];
            if (token[7] == "any") {
                var dstIP = "any";
                var dstMask = "";
            } else if (token[7] == "host") {
                var dstIP = token[8];
                var dstMask = "255.255.255.255";
            } else {
                var dstIP = token[7];
                var dstMask = token[8];
            }
        }

        if (!ACLs.hasOwnProperty(token[1])) {  // object doesn't exist yet, lets create it
           ACLs[token[1]] = []; 
        }
        // Add a new line to the ACLs variable
        ACLs[token[1]].push([token[3], token[4], srcIP, srcMask, dstIP, dstMask]);
    }

    function processGlobal(token, line1) {
        // 0           1                  2          3             4       5
        // global      (outside)          3          172.27.27.27 
        // global      (outside)          1          interface
        // global      (outside)          81         10.42.42.1    netmask 255.255.255.128

        output.push("! Processing global: " + line1);

        // take out "(" and ")"
        var globalInterface = token[1].replace(/\(/,"");
        globalInterface = globalInterface.replace(/\)/,"");


        // Print the object for the global PAT IP
        var mappedIP = token[3];
        var obj2 = "OBJ-" + mappedIP;
        var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        var ipArray = mappedIP.match(ipPattern);


        var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})-(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        var ipRangeArray = mappedIP.match(ipPattern);
        // ipRangeArray == ["192.168.250.141-192.168.250.190", "192", "168", "250", "141", "192", "168", "250", "190"]

        if ( (ipArray == null) && (mappedIP != "interface") && (ipRangeArray == null) ) {
            output.push("! Error, invalid IP address in statement.\n");
            return;
        }

        // Create global PAT IP object
        if (ipRangeArray != null) {
            obj2 = "OBJ-" + ipRangeArray[0];
            output.push("object network " + obj2);
            output.push(" range " + ipRangeArray[1] + "." + ipRangeArray[2] + "." + ipRangeArray[3] + "." + ipRangeArray[4] + " " + ipRangeArray[5] + "." + ipRangeArray[6] + "." + ipRangeArray[7] + "." + ipRangeArray[8]);
        } else if (token[4] == "netmask") {
            var cidr = convertNetmaskToCIDR(token[5]);
            var netIP = determineNetworkAddress(mappedIP,token[5]);
            obj2 = "OBJ-" + netIP + "-" + cidr; 
            output.push("object network " + obj2);
            output.push("  subnet " + netIP + " " + token[5]);            
        } else if (mappedIP != "interface") {
            output.push("object network " + obj2);
            output.push("  host " + mappedIP);
        } else if (mappedIP == "interface") {
            obj2 = "interface";
        }

        // Add global data to globalPAT hash
        globalPAT.push([token[2], globalInterface, token[3], obj2]);
        output.push("");
    }

    function processStatic(token) {
           // 0      1                2             3           4       5               6     7         8
           // static (inside,outside) 192.168.55.27 access-list ACL-NAT
           // static (dmz,outside)    tcp           interface   8080    172.16.0.10     www   netmask   255.255.255.255
           // static (Inside,Outside) 55.55.55.2    192.168.1.2 netmask 255.255.255.255
           // static (INSIDE,DMZ)     192.168.100.4 172.24.2.49 netmask 255.255.255.255 tcp   255       2000
            var invalid = 0;
            token[2] = token[2].toUpperCase();
            if ( (token[2] == "TCP") || (token[2] == "UDP") ) {
                // static (dmz,outside) tcp interface 8080 172.16.0.10 www netmask 255.255.255.255
                var mappedIP = token[3];
                var realIP = token[5];
                var netmask = token[8];
                var convertPorts = true;
            } else {
                // static (Inside,Outside) 55.55.55.2 192.168.1.2 netmask 255.255.255.255
                var mappedIP = token[2];
                var realIP = token[3];
                var netmask = token[5];
                var convertPorts = false;
            }

            if (token[token.length - 1] == "dns") {
                var displayDns = " dns";
            } else {
                var displayDns = "";
            }

            var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
            var ipArray = mappedIP.match(ipPattern);
            if ( (ipArray == null) && (mappedIP != "interface") ) {
                invalid++;
            }

            var obj1 = "OBJ-" + realIP;
            var obj2 = "OBJ-" + mappedIP;
              
            if (invalid > 0) {
                    output.push("! Error: IP address invalid");
                    output.push("");
            } else {

                    if (token[3] == "access-list") {
                        var ACLname = token[4];
                        var intsraw = token[1];
                        intsraw = intsraw.replace(/\(/, "");
                        intsraw = intsraw.replace(/\)/, "");
                        var ints = intsraw.split(",");
                        var realInt = ints[0];
                        var mappedInt = ints[1];
                        createNATfromACL(ACLname, realInt, mappedInt, obj2, "", "");

                    } else {
                            if (netmask == "255.255.255.255") {
                                if (realIP == "interface") {
                                    obj1 = "interface";                                  
                                } else {
                                    output.push("object network " + obj1);
                                    output.push("  host " + realIP);
                                }
                                if (mappedIP == "interface") {
                                    obj2 = "interface";
                                } else {
                                    output.push("object network " + obj2);
                                    output.push("  host " + mappedIP);
                                }
                            } else {
                                    var cidr = convertNetmaskToCIDR(netmask);
                                    var netIP = determineNetworkAddress(realIP,netmask);
                                    obj1 = "OBJ-" + netIP + "-" + cidr;
                                    output.push("object network " + obj1);
                                    output.push("  subnet " + netIP + " " + netmask);
                                    var cidr = convertNetmaskToCIDR(netmask);
                                    var netIP = determineNetworkAddress(mappedIP,netmask);
                                    obj2 = "OBJ-" + netIP + "-" + cidr;
                                    output.push("object network " + obj2);
                                    output.push("  subnet " + netIP + " " + netmask);
                            }
                            if (convertPorts == true) {
                                var svcObj1 = "OBJ-" + token[2] + "-" + token[4];
                                var svcObj2 = "OBJ-" + token[2] + "-" + token[6];
                                output.push("object service " + svcObj1);
                                output.push("  service " + token[2] + " source eq " + token[4]);
                                output.push("object service " + svcObj2);
                                output.push("  service " + token[2] + " source eq " + token[6]);
                                // nat (INSIDE,OUTSIDE) source static obj-172.16.200.200 obj-11.11.11.11 service obj-TCP-80 obj-TCP-8888
                                output.push("nat " + token[1] + " source static " + obj1 + " " + obj2 + " service " + svcObj2 + " " + svcObj1 + displayDns);
                            } else {
                                // nat (INSIDE,OUTSIDE) source static OBJ-192.168.1.2 OBJ-55.55.55.2
                                output.push("nat " + token[1] + " source static " + obj1 + " " + obj2 + displayDns);
                            }
                    }

                    if (token[6] == "tcp") {
                        var clientMax = token[7];
                        var embMax = token[8];
                        obj2 = "OBJ-" + netIP + "-" + cidr;

                        output.push("access-list ACL-CONN-SETTINGS-" + aclCounter + " extended permit tcp object " + obj2 + " any");
                        output.push("class-map CLASS-CONN-TCP-SETTTINGS-" + aclCounter);
                        output.push(" match access-list ACL-CONN-SETTINGS-" + aclCounter);
                        output.push("policy-map global_policy");
                        output.push(" class CLASS-CONN-TCP-SETTTINGS-" + aclCounter);
                        output.push("  set connection per-client-max " + clientMax + " per-client-embryonic-max " + embMax);
                        output.push("! Warning: Verify the policy-map is the correct one.");

                        // policy-map global_policy
                        // class inspection_default

                        // access-list acl-conn-param-tcp-01 extended permit tcp host 172.24.2.49 any
                        // class-map class-conn-param-tcp-01
                        // match access-list acl-conn-param-tcp-01
                        // policy-map policy-conn-param-inside
                        // class class-conn-param-tcp-01
                        // set connection per-client-max 255 per-client-embryonic-max 2000
                        aclCounter++;
                    }
                    output.push("");
            }
    }

    function convertNetmaskToCIDR(maskValue) {
        if (maskValue == "0.0.0.0") return 0;
        if (maskValue == "128.0.0.0") return 1;
        if (maskValue == "192.0.0.0") return 2;
        if (maskValue == "224.0.0.0") return 3;
        if (maskValue == "240.0.0.0") return 4;
        if (maskValue == "248.0.0.0") return 5;
        if (maskValue == "252.0.0.0") return 6;
        if (maskValue == "254.0.0.0") return 7;
        if (maskValue == "255.0.0.0") return 8;

        if (maskValue == "255.128.0.0") return 9;
        if (maskValue == "255.192.0.0") return 10;
        if (maskValue == "255.224.0.0") return 11;
        if (maskValue == "255.240.0.0") return 12;
        if (maskValue == "255.248.0.0") return 13;
        if (maskValue == "255.252.0.0") return 14;
        if (maskValue == "255.254.0.0") return 15;
        if (maskValue == "255.255.0.0") return 16;

        if (maskValue == "255.255.128.0") return 17;
        if (maskValue == "255.255.192.0") return 18;
        if (maskValue == "255.255.224.0") return 19;
        if (maskValue == "255.255.240.0") return 20;
        if (maskValue == "255.255.248.0") return 21;
        if (maskValue == "255.255.252.0") return 22;
        if (maskValue == "255.255.254.0") return 23;
        if (maskValue == "255.255.255.0") return 24;

        if (maskValue == "255.255.255.128") return 25;
        if (maskValue == "255.255.255.192") return 26;
        if (maskValue == "255.255.255.224") return 27;
        if (maskValue == "255.255.255.240") return 28;
        if (maskValue == "255.255.255.248") return 29;
        if (maskValue == "255.255.255.252") return 30;
        if (maskValue == "255.255.255.254") return 31;
        if (maskValue == "255.255.255.255") return 32;
    }
    function determineNetworkAddress(ip,netmask) {
        var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        var netmaskArray = netmask.match(ipPattern);
        var ipArray = ip.match(ipPattern);
        var networkIP = "";
        for (i = 1; i < 5; i++) {
            var hosts = 0;
            thisSegment = parseInt(ipArray[i]);
            if (netmaskArray[i] == 255) {
                networkIP = networkIP + thisSegment;
            } else {
                hosts = 256 - netmaskArray[i];
                for (var j = 0; j < 256; j=j+hosts) {
                    if ( (thisSegment >= j ) && (thisSegment < j+hosts)) {
                        networkIP = networkIP + j;

                        break;
                    }
                    
                }
            }
            if (i < 4) networkIP = networkIP + ".";
       }
        return networkIP;
    }
    function trim(stringToTrim) {
        stringToTrim = stringToTrim.replace(/\s+/g, " ");
        stringToTrim = stringToTrim.replace(/[ ]{2,}/gi," ");
        stringToTrim = stringToTrim.replace(/\n /,"\n");
        return stringToTrim.replace(/^\s+|\s+$/g,"");
    }
});