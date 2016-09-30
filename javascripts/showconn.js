$(document).ready(function() {
	$("#analyze").click(function(){
		var showconnblob = document.conns.showconninput.value;
		    // remove double spaces
		showconnblob = showconnblob.replace("  ", " ");
		    // remove trailing and leading spaces (basically doing a trim)
		showconnblob = showconnblob.replace(/(^\s*)|(\s*$)/gi,"");
		showconnblob = showconnblob.replace(/[ ]{2,}/gi," ");
		showconnblob = showconnblob.replace(/\n /,"\n");

		// reset output
		$("#topTalkers").html("");
		$("#topInboundPorts").html("");
		$("#topOutboundPorts").html("");
		$("#topInboundHalfs").html("");
		$("#connTypes").html("");
		$("#topUDPsrcPorts").html(table);
		$("#topUDPdstPorts").html(table);



		var output = [];
		var showconn = showconnblob.split('\n');

        var showconnTCP = [];
        var showconnUDP = [];
        var showconnICMP = [];
        var showconnGRE = [];
        var showconnESP = [];
        var flagTypes = [];
        var connsInbound = [];
        var connsInboundPorts = [];
        var connsOutbound = [];
        var connsOutboundPorts = {};
        var connsHalfIn = [];
        var connsHalfInPorts = [];
        var connsHalfOut = [];
        var connsHalfOutPorts = [];
        var UDPsrcPortsCount = [];
        var UDPdstPortsCount = [];

		var showconnTokenized = [];

        // Break the show conn up into the different protocols
        for (var i=0; i < showconn.length; i++) {
			showconn[i] = showconn[i].replace(/\,/gi,""); // Remove all commas
			var eachWord = showconn[i].split(" ");
			eachWord[8] = parseInt(eachWord[8]);

			// look for object-group names
			if (eachWord[0] == "TCP") {
				showconnTCP.push(showconn[i]);
				showconnTokenized.push(eachWord);
			} else if (eachWord[0] == "UDP") {
				showconnTokenized.push(eachWord);
				showconnUDP.push(showconn[i]);
				var srcipPort = eachWord[2].split(":");
				var srcport = srcipPort[1];	
				var dstipPort = eachWord[4].split(":");
				var dstport = dstipPort[1];
				UDPsrcPortsCount[srcport] = UDPsrcPortsCount[srcport] ? UDPsrcPortsCount[srcport]+1 : 1;
				UDPdstPortsCount[dstport] = UDPdstPortsCount[dstport] ? UDPdstPortsCount[dstport]+1 : 1;

			} else if (eachWord[0] == "ICMP") {
				showconnTokenized.push(eachWord);
				showconnICMP.push(showconn[i]);
			} else if (eachWord[0] == "GRE") {
				showconnTokenized.push(eachWord);
				showconnGRE.push(showconn[i]);
			} else if (eachWord[0] == "ESP") {
				showconnTokenized.push(eachWord);
				showconnESP.push(showconn[i]);
			} 

			var bytes = eachWord[8];
			var flags = eachWord[10];

			if (flags in flagTypes) {
				flagTypes[flags] ++;
			} else {
				flagTypes[flags] = 1;
			}

			if (flags == 'UIO') {
				connsOutbound.push(eachWord);
				var ipPort = eachWord[2].split(":");
				var port = eachWord[0] + " " + ipPort[1];
				connsOutboundPorts[port] = connsOutboundPorts[port] ? connsOutboundPorts[port]+1 : 1;

			} else if (flags == 'UIOB') {
				connsInbound.push(eachWord);
				var ipPort = eachWord[4].split(":");
				var port = eachWord[0] + " " + ipPort[1];
				connsInboundPorts[port] = connsOutboundPorts[port] ? connsOutboundPorts[port]+1 : 1;


			} else if (flags == 'SaAB') {
				var ipPort = eachWord[2].split(":");
				connsHalfIn.push(eachWord[1] + " " + ipPort[0] + " " + eachWord[3] + " " + eachWord[4] );
				// TCP DMZ 10.48.1.132:57155 INSIDE  10.69.250.157:9999, idle 0:00:01, bytes 0, flags SaAB

			} else if (flags == 'saA') {
				connsHalfOut.push(eachWord);
			}


		}

		var UDPsrcPortsCountSorted = getSortedKeys(UDPsrcPortsCount);
		UDPsrcPortsCountSorted.reverse();
		var UDPdstPortsCountSorted = getSortedKeys(UDPdstPortsCount);
		UDPdstPortsCountSorted.reverse();


		var connsHalfInCounts = {};
		for (var i = 0; i < connsHalfIn.length; i++) {
		    connsHalfInCounts[connsHalfIn[i]] = 1 + (connsHalfInCounts[connsHalfIn[i]] || 0);
		}
		var connsHalfInSorted = getSortedKeys(connsHalfInCounts);
		connsHalfInSorted.reverse();

		var connsOutboundPortsSorted = getSortedKeys(connsOutboundPorts);
		connsOutboundPortsSorted.reverse();
		var connsInboundPortsSorted = getSortedKeys(connsInboundPorts);
		connsInboundPortsSorted.reverse();

		// sort the flag types to put the highest count first
		var flagTypesSorted = getSortedKeys(flagTypes);
		flagTypesSorted.reverse();

		// Sort the conns so the largest bytes are first
		showconnTokenized.sort((function(index){
		    return function(a, b){
		        return (a[index] === b[index] ? 0 : (a[index] < b[index] ? -1 : 1));
		    };
		})(8));
		showconnTokenized.reverse();


		// display results to page
		var totalConns = showconnTCP.length + showconnUDP.length + showconnICMP.length + showconnGRE.length + showconnESP.length;
		$("#totalconns").text(totalConns.toLocaleString());
		$("#tcpconns").text(showconnTCP.length.toLocaleString());
		$("#udpconns").text(showconnUDP.length.toLocaleString());
		$("#icmpconns").text(showconnICMP.length.toLocaleString());
		$("#greconns").text(showconnGRE.length.toLocaleString());
		$("#espconns").text(showconnESP.length.toLocaleString());

		// format and display the top talkers table
		if (totalConns >= 10) {
			var topTalkersTable = '<table class="table table-striped"><caption><big><strong>Top 10 Top Talkers</strong></big></caption>';
			topTalkersTable = topTalkersTable + '<thead><tr><td>Proto</td><td>Src Int</td><td>Src IP:Port</td><td>Dst Int</td><td>Dst IP:Port</td><td>Idle</td><td>Bytes</td><td>Flags</td></tr></thead>';
        	for (var i=0; i <= 9; i++) {
				topTalkersTable = topTalkersTable + '<tr>';
				for (var j=0; j < showconnTokenized[i].length; j++) {
					if ( (j==5) || (j==7) || (j==9)) {
						continue; // skip the idle/bytes/flags columns
					} else if (j==8) {
						showconnTokenized[i][j] = showconnTokenized[i][j].toLocaleString();
					}
					topTalkersTable = topTalkersTable + '<td>' + showconnTokenized[i][j] + '</td>';
				}
				topTalkersTable = topTalkersTable + '</tr>';
			}
			topTalkersTable = topTalkersTable + '</table>';
			$("#topTalkers").html(topTalkersTable);
		}

		if (Object.keys(flagTypes).length > 1) {
			var flagTypesTable = '<table class="table table-striped"><caption><strong>Connection Types</strong></caption>';
			flagTypesTable = flagTypesTable + '<thead><tr><td>Flag</td><td>Count</td><td><a href="/understanding-cisco-asa-connection-flags/">Definition</a></td></tr></thead>';
			for (var i=0; i < Object.keys(flagTypes).length; i++) {
				if ( (flagTypesSorted[i] == 'undefined') || (flagTypesSorted[i] == '-')) {
					continue; // skip these
				}
				flagTypesTable = flagTypesTable + '</tr>';
				flagTypesTable = flagTypesTable + '<td>' + flagTypesSorted[i] + '</td><td>' + flagTypes[flagTypesSorted[i]] + '</td>';
				if (flagTypesSorted[i] == 'UIO') {
					flagTypesTable = flagTypesTable + '<td>Outbound Full Connection</td>';
				} else if (flagTypesSorted[i] == 'UIOB') {
					flagTypesTable = flagTypesTable + '<td>Inbound Full Connection</td>';
				} else if (flagTypesSorted[i] == 'SaAB') {
					flagTypesTable = flagTypesTable + '<td>Inbound SYN (Half open connection)</td>';
				} else if (flagTypesSorted[i] == 'saA') {
					flagTypesTable = flagTypesTable + '<td>Outbound SYN (Half open connection)</td>';
				} else if (flagTypesSorted[i] == 'aB') {
					flagTypesTable = flagTypesTable + '<td>Inbound SYN+ACK</td>';
				} else if (flagTypesSorted[i] == 'A') {
					flagTypesTable = flagTypesTable + '<td>Outbound SYN+ACK</td>';
				} else if (flagTypesSorted[i] == 'U') {
					flagTypesTable = flagTypesTable + '<td>Outbound ACK</td>';
				} else if (flagTypesSorted[i] == 'UB') {
					flagTypesTable = flagTypesTable + '<td>Inbound ACK</td>';
				} else if (flagTypesSorted[i] == 'UFRIO') {
					flagTypesTable = flagTypesTable + '<td>Closing connection</td>';
				} else if (flagTypesSorted[i] == 'UIB') {
					flagTypesTable = flagTypesTable + '<td>Inbound data</td>';
				} else if (flagTypesSorted[i] == 'h') {
					flagTypesTable = flagTypesTable + '<td>H.225.0</td>';
				} else if (flagTypesSorted[i] == 'UFIO') {
					flagTypesTable = flagTypesTable + '<td>Closing connection</td>';
				} else if (flagTypesSorted[i] == 'H') {
					flagTypesTable = flagTypesTable + '<td>H.323</td>';
				} else if (flagTypesSorted[i] == 'i') {
					flagTypesTable = flagTypesTable + '<td>incomplete</td>';
				} else if (flagTypesSorted[i] == 'k') {
					flagTypesTable = flagTypesTable + '<td>Skinny media</td>';

				} else {	
					flagTypesTable = flagTypesTable + '<td></td>';
				} 
				flagTypesTable = flagTypesTable + '</tr>';
			}
			flagTypesTable = flagTypesTable + '</table>';
			$("#connTypes").html(flagTypesTable);

		}



		if (Object.keys(connsOutboundPorts).length > 1) {
			var table = '<table class="table table-striped"><caption><strong>Top Outbound TCP Ports</strong></caption>';
			table = table + '<thead><tr><td>Port</td><td>Count</td></tr></thead>';
			for (var i=0; i < Object.keys(connsOutboundPorts).length; i++) {
				if (connsOutboundPorts[connsOutboundPortsSorted[i]] < 3) {
					continue; // skip values of 0, 1, 2
				}
				table = table + '</tr>';
				table = table + '<td>' + connsOutboundPortsSorted[i] + '</td><td>' + connsOutboundPorts[connsOutboundPortsSorted[i]] + '</td>';

				table = table + '</tr>';
				if (i > 9) {
					break; // lets just do top 10
				}
			}
			table = table + '</table>';
			$("#topOutboundPorts").html(table);
		}

		if (Object.keys(connsInboundPorts).length > 1) {
			var table = '<table class="table table-striped"><caption><strong>Top Inbound TCP Ports</strong></caption>';
			table = table + '<thead><tr><td>Port</td><td>Count</td></tr></thead>';
			for (var i=0; i < Object.keys(connsInboundPorts).length; i++) {
				if (connsInboundPorts[connsInboundPortsSorted[i]] < 3) {
					continue; // skip values of 0, 1, 2
				}

				table = table + '</tr>';
				table = table + '<td>' + connsInboundPortsSorted[i] + '</td><td>' + connsInboundPorts[connsInboundPortsSorted[i]] + '</td>';

				table = table + '</tr>';
				if (i > 9) {
					break; // lets just do top 10
				}
			}
			table = table + '</table>';
			$("#topInboundPorts").html(table);
		}

		if (Object.keys(connsHalfInCounts).length > 1) {
			var table = '<table class="table table-striped"><caption><strong>Top Inbound Half Open TCP Connections (a large amount of these may indicate a problem)</strong></caption>';
			table = table + '<thead><tr><td>Src Int/Src IP/Dst Int/Dst IP:Dst Port</td><td>Count</td></tr></thead>';
			for (var i=0; i < Object.keys(connsHalfInSorted).length; i++) {
				if (connsHalfInCounts[connsHalfInSorted[i]] < 3) {
					continue; // skip values of 0, 1, 2
				}
				table = table + '</tr>';
				table = table + '<td>' + connsHalfInSorted[i] + '</td><td>' + connsHalfInCounts[connsHalfInSorted[i]] + '</td>';
				table = table + '</tr>';
				if (i > 9) {
					break; // lets just do top 10
				}
			}
			table = table + '</table>';
			$("#topInboundHalfs").html(table);
		}


		if (Object.keys(UDPsrcPortsCount).length > 1) {
			var table = '<table class="table table-striped"><caption><strong>Top UDP Source Ports -OR- Inbound Connections (omitting high ports)</strong></caption>';
			table = table + '<thead><tr><td>Port</td><td>Count</td></tr></thead>';
			for (var i=0; i < Object.keys(UDPsrcPortsCountSorted).length; i++) {
				if (UDPsrcPortsCount[UDPsrcPortsCountSorted[i]] < 3) {
					continue; // skip values of 0, 1, 2
				} else if (UDPsrcPortsCountSorted[i] > 32000) {
					continue; // skip high ports
				}

				table = table + '</tr>';
				table = table + '<td>' + UDPsrcPortsCountSorted[i] + '</td><td>' + UDPsrcPortsCount[UDPsrcPortsCountSorted[i]] + '</td>';
				table = table + '</tr>';
				if (i > 9) {
					break; // lets just do top 10
				}
			}
			table = table + '</table>';
			$("#topUDPsrcPorts").html(table);
		}


		if (Object.keys(UDPdstPortsCount).length > 1) {
			var table = '<table class="table table-striped"><caption><strong>Top UDP Destination Ports -OR- Outbound Connections (omitting high ports)</strong></caption>';
			table = table + '<thead><tr><td>Port</td><td>Count</td></tr></thead>';
			for (var i=0; i < Object.keys(UDPdstPortsCountSorted).length; i++) {
				if (UDPdstPortsCount[UDPdstPortsCountSorted[i]] < 3) {
					continue; // skip values of 0, 1, 2
				} else if (UDPdstPortsCountSorted[i] > 32000) {
					continue; // skip high ports
				}				table = table + '</tr>';
				table = table + '<td>' + UDPdstPortsCountSorted[i] + '</td><td>' + UDPdstPortsCount[UDPdstPortsCountSorted[i]] + '</td>';
				table = table + '</tr>';
				if (i > 9) {
					break; // lets just do top 10
				}
			}
			table = table + '</table>';
			$("#topUDPdstPorts").html(table);
		}


	});
	$("#demo").click(function(){
		var demodata = 'ASA1/pri/act# sh conn\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.2.167:51084, idle 0:00:11, bytes 8100, flags UIO\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.2.167:51083, idle 0:00:11, bytes 1450, flags UIO\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.2.167:51081, idle 0:00:11, bytes 2810, flags UIO\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.2.167:51082, idle 0:00:11, bytes 10857, flags UIO\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.2.167:51080, idle 0:00:11, bytes 1434, flags UIO\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.2.167:51079, idle 0:00:11, bytes 22960, flags UIO\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.246.91:51147, idle 0:00:10, bytes 9674, flags UIO\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.246.91:51146, idle 0:00:11, bytes 21305, flags UIO\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.246.103:51106, idle 0:00:02, bytes 361985, flags UFRIO\n' +
		'TCP EXTRANET 122.122.122.122:443 INSIDE 172.24.246.93:63294, idle 0:00:03, bytes 50494, flags UFRIO\n' +
		'TCP EXTRANET 122.122.122.123:443 INSIDE 172.24.2.167:51076, idle 0:00:30, bytes 394, flags UIO\n' +
		'TCP EXTRANET 122.122.122.123:443 INSIDE 172.24.2.167:51075, idle 0:00:30, bytes 394, flags UIO\n' +
		'TCP EXTRANET 122.122.122.123:443 INSIDE 172.24.2.167:51074, idle 0:00:30, bytes 394, flags UIO\n' +
		'TCP EXTRANET 122.122.122.123:443 INSIDE 172.24.2.167:51073, idle 0:00:30, bytes 394, flags UIO\n' +
		'TCP EXTRANET 122.122.122.123:443 INSIDE 172.24.2.167:51072, idle 0:00:20, bytes 9274, flags UFRIO\n' +
		'UDP WIRELESS 10.96.18.11:12000 INSIDE 172.24.2.222:12000, idle 0:01:13, bytes 599348, flags -\n' +
		'ICMP WIRELESS 10.118.26.67:0 INSIDE 172.24.120.33:7, idle 0:00:00, bytes 1950432\n' +
		'UDP WIRELESS 172.18.147.17:137 INSIDE 172.24.12.28:137, idle 0:01:19, bytes 94200, flags -\n' +
		'GRE WIRELESS 172.18.147.17:0 INSIDE 172.18.147.105:0, idle 0:00:12, bytes 3769050, flags E\n' +
		'GRE WIRELESS 172.18.147.17:0 INSIDE 172.18.147.105:0, idle 0:00:12, bytes 3769050, flags E\n' +
		'GRE WIRELESS 172.18.147.17:0 INSIDE 172.18.147.105:0, idle 0:00:12, bytes 3769050, flags E\n' +
		'TCP WIRELESS 200.200.200.200:17243 INSIDE 172.24.89.251:1000, idle 0:00:56, bytes 7772, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17310 INSIDE 172.24.56.251:1000, idle 0:00:02, bytes 13409, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17342 INSIDE 172.24.193.251:1000, idle 0:00:25, bytes 11662, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17130 INSIDE 172.24.121.161:1043, idle 0:00:07, bytes 6588, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17247 INSIDE 172.24.86.27:1000, idle 0:00:04, bytes 159, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17006 INSIDE 172.24.184.251:1000, idle 0:00:05, bytes 10457, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17197 INSIDE 172.24.211.123:1000, idle 0:00:42, bytes 6795, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17380 INSIDE 172.24.220.59:1000, idle 0:00:50, bytes 1057, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17388 INSIDE 172.24.220.219:1000, idle 0:00:24, bytes 6478, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17206 INSIDE 172.24.88.251:1150, idle 0:00:12, bytes 10199, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17511 INSIDE 172.24.214.153:1000, idle 0:00:15, bytes 1468, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17109 INSIDE 172.24.100.251:1000, idle 0:00:59, bytes 7700, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17333 INSIDE 172.24.187.251:1000, idle 0:00:03, bytes 9468, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17364 INSIDE 172.24.222.219:1000, idle 0:00:35, bytes 13816, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17158 INSIDE 172.24.90.251:1457, idle 0:00:49, bytes 8203, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17394 INSIDE 172.24.222.155:1000, idle 0:00:03, bytes 7967, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17265 INSIDE 172.24.221.251:1000, idle 0:00:32, bytes 5344, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17010 INSIDE 172.24.93.251:1000, idle 0:00:50, bytes 4743, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17374 INSIDE 172.24.219.91:1000, idle 0:00:05, bytes 10758, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17018 INSIDE 172.24.87.101:1062, idle 0:00:58, bytes 1837, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17235 INSIDE 172.24.167.251:1000, idle 0:00:42, bytes 8074, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17016 INSIDE 172.24.177.251:1000, idle 0:00:06, bytes 7847, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17430 INSIDE 172.24.224.251:1000, idle 0:00:24, bytes 8255, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17013 INSIDE 172.24.213.91:1030, idle 0:00:59, bytes 9336, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17195 INSIDE 172.24.175.251:1074, idle 0:00:31, bytes 219, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17002 INSIDE 172.24.216.251:1000, idle 0:00:13, bytes 11869, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17245 INSIDE 172.24.139.251:1000, idle 0:00:41, bytes 9819, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17340 INSIDE 172.24.101.251:1000, idle 0:00:31, bytes 224, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17165 INSIDE 172.24.122.105:1000, idle 0:00:42, bytes 5602, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17052 INSIDE 172.24.211.251:1000, idle 0:00:16, bytes 12652, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17272 INSIDE 172.24.218.91:1000, idle 0:00:56, bytes 14242, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17260 INSIDE 172.24.215.219:1000, idle 0:00:38, bytes 7921, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17131 INSIDE 172.24.87.161:1000, idle 0:00:28, bytes 43736, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17254 INSIDE 172.24.121.9:1079, idle 0:00:04, bytes 190254, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17088 INSIDE 172.24.87.65:1051, idle 0:00:49, bytes 34873, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17294 INSIDE 172.24.122.185:1000, idle 0:00:39, bytes 84930, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17033 INSIDE 172.24.121.193:1000, idle 0:00:48, bytes 72827, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17031 INSIDE 172.24.4.191:1000, idle 0:00:50, bytes 57019, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17015 INSIDE 172.24.4.190:1000, idle 0:00:22, bytes 63535, flags UIO\n' +
		'TCP WIRELESS 200.200.200.200:17372 INSIDE 172.24.122.225:1000, idle 0:00:38, bytes 47937, flags UIO\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:61256, idle 0:00:00, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:58868, idle 0:00:06, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:51736, idle 0:00:11, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:56946, idle 0:00:17, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:51319, idle 0:00:22, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:56560, idle 0:00:28, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:50862, idle 0:00:33, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:61470, idle 0:00:38, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:51141, idle 0:00:44, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:51491, idle 0:00:49, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:53644, idle 0:00:55, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:53619, idle 0:01:00, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:50111, idle 0:01:06, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:59333, idle 0:01:11, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:50109, idle 0:01:17, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:52581, idle 0:01:22, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:52968, idle 0:01:28, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:57419, idle 0:01:33, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:50398, idle 0:01:39, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:50766, idle 0:01:44, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:56500, idle 0:01:50, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:61968, idle 0:01:55, bytes 919, flags -\n' +
		'UDP DMZ 192.168.100.100:161 INSIDE 172.25.243.10:60186, idle 0:02:00, bytes 919, flags -\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61471, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61470, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60227, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60226, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55239, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55238, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61439, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61438, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61437, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60194, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60193, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60192, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55205, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55204, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55203, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61411, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61410, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61409, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60166, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60165, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60164, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55177, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55176, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55175, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61374, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61373, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61372, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60129, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60128, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60127, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55140, idle 0:01:13, bytes 2471046, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55139, idle 0:01:13, bytes 2471158, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55138, idle 0:01:13, bytes 2490461, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61342, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61341, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61340, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60097, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60096, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60095, idle 0:01:13, bytes 2469715, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55108, idle 0:01:13, bytes 2512569, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55107, idle 0:01:13, bytes 4706295, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55106, idle 0:01:13, bytes 5528203, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61306, idle 0:01:13, bytes 2469821, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61305, idle 0:01:13, bytes 2469821, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61304, idle 0:01:13, bytes 2469821, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60061, idle 0:01:13, bytes 2469821, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60060, idle 0:01:13, bytes 2469821, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60059, idle 0:01:13, bytes 2469821, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55072, idle 0:01:13, bytes 11842141, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55071, idle 0:01:13, bytes 9338270, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55070, idle 0:01:13, bytes 18305178, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61253, idle 0:00:38, bytes 2728963, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61252, idle 0:00:02, bytes 194130653, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.10:61251, idle 0:00:26, bytes 713259675, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60008, idle 0:01:13, bytes 2469821, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60007, idle 0:01:13, bytes 2469821, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64002 INSIDE 172.25.243.10:60006, idle 0:01:13, bytes 2469821, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55019, idle 0:01:13, bytes 23398842, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55018, idle 0:01:13, bytes 27660980, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.10:55017, idle 0:01:13, bytes 61326598, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53429, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53428, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53407, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53406, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53405, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49656, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49655, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53383, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53381, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53380, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49631, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49630, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49629, idle 0:01:00, bytes 2479361, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53356, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53355, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53354, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49605, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49604, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49603, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49577, idle 0:01:00, bytes 16511737, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53330, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53329, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53328, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49579, idle 0:01:00, bytes 2580362, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49578, idle 0:01:00, bytes 2581607, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53304, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53303, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53302, idle 0:01:00, bytes 2479467, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49553, idle 0:01:00, bytes 3439547, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49552, idle 0:01:00, bytes 2644907, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49551, idle 0:01:00, bytes 7064019, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53277, idle 0:01:00, bytes 7237563, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53276, idle 0:01:00, bytes 485473508, flags UIO\n' +
		'TCP DMZ 192.168.100.100:7001 INSIDE 172.25.243.12:53275, idle 0:00:39, bytes 3206023, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49526, idle 0:01:00, bytes 43237675, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49525, idle 0:01:00, bytes 18478456, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49524, idle 0:01:00, bytes 1086507910, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49498, idle 0:01:00, bytes 20889842, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49499, idle 0:01:00, bytes 30157214, flags UIO\n' +
		'TCP DMZ 192.168.100.100:64001 INSIDE 172.25.243.12:49500, idle 0:01:00, bytes 159941743, flags UIO\n' +
		'TCP OUTSIDE 172.56.20.2:63128 DMZ 192.168.100.81:443, idle 0:00:00, bytes 5190, flags UIOB\n' +
		'TCP OUTSIDE 75.108.173.190:58873 DMZ 192.168.100.81:443, idle 0:00:00, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 107.77.168.43:50494 DMZ 192.168.100.81:443, idle 0:00:00, bytes 32378, flags UIOB\n' +
		'TCP OUTSIDE 75.108.173.190:58874 DMZ 192.168.100.81:443, idle 0:00:00, bytes 4942, flags UIOB\n' +
		'TCP OUTSIDE 166.176.122.89:65006 DMZ 192.168.100.81:443, idle 0:00:00, bytes 83402, flags UfIOB\n' +
		'TCP OUTSIDE 205.197.242.186:9438 DMZ 192.168.100.81:443, idle 0:00:01, bytes 4075, flags UIOB\n' +
		'TCP OUTSIDE 205.197.242.186:9439 DMZ 192.168.100.81:443, idle 0:00:01, bytes 4075, flags UIOB\n' +
		'TCP OUTSIDE 205.197.242.186:9437 DMZ 192.168.100.81:443, idle 0:00:01, bytes 4075, flags UIOB\n' +
		'TCP OUTSIDE 205.197.242.186:9436 DMZ 192.168.100.81:443, idle 0:00:01, bytes 4075, flags UIOB\n' +
		'TCP OUTSIDE 205.197.242.186:9435 DMZ 192.168.100.81:443, idle 0:00:01, bytes 4075, flags UIOB\n' +
		'TCP OUTSIDE 205.197.242.186:9434 DMZ 192.168.100.81:443, idle 0:00:01, bytes 4075, flags UIOB\n' +
		'TCP OUTSIDE 205.197.242.186:9433 DMZ 192.168.100.81:443, idle 0:00:01, bytes 4075, flags UIOB\n' +
		'TCP OUTSIDE 172.56.23.214:31627 DMZ 192.168.100.81:443, idle 0:00:17, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 172.56.23.214:38127 DMZ 192.168.100.81:443, idle 0:00:17, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 172.56.23.214:35015 DMZ 192.168.100.81:443, idle 0:00:17, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 172.56.23.214:26096 DMZ 192.168.100.81:443, idle 0:00:17, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 64.25.66.112:25037 DMZ 192.168.100.81:443, idle 0:00:18, bytes 4462, flags UIOB\n' +
		'TCP OUTSIDE 66.87.98.240:10790 DMZ 192.168.100.81:80, idle 0:00:28, bytes 0, flags UB\n' +
		'TCP OUTSIDE 208.110.200.3:58983 DMZ 192.168.100.81:443, idle 0:00:40, bytes 537, flags UIOB\n' +
		'TCP OUTSIDE 108.223.135.201:62522 DMZ 192.168.100.81:443, idle 0:01:09, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 76.185.17.85:62897 DMZ 192.168.100.81:443, idle 0:01:25, bytes 4645, flags UIOB\n' +
		'TCP OUTSIDE 74.197.46.22:50067 DMZ 192.168.100.81:443, idle 0:00:18, bytes 38253, flags UFRIOB\n' +
		'TCP OUTSIDE 66.87.99.180:3569 DMZ 192.168.100.81:443, idle 0:00:09, bytes 4689, flags UfrIOB\n' +
		'TCP OUTSIDE 73.32.163.43:58020 DMZ 192.168.100.81:443, idle 0:01:25, bytes 4225, flags UfFRIOB\n' +
		'TCP OUTSIDE 73.32.163.43:58019 DMZ 192.168.100.81:443, idle 0:01:26, bytes 4481, flags UfFRIOB\n' +
		'TCP OUTSIDE 73.32.163.43:58017 DMZ 192.168.100.81:443, idle 0:01:26, bytes 5822, flags UFRIOB\n' +
		'TCP OUTSIDE 73.32.163.43:58012 DMZ 192.168.100.81:443, idle 0:01:27, bytes 5870, flags UFRIOB\n' +
		'TCP OUTSIDE 73.32.163.43:58009 DMZ 192.168.100.81:443, idle 0:01:27, bytes 23130, flags UFRIOB\n' +
		'TCP OUTSIDE 24.28.160.3:50574 DMZ 192.168.100.81:80, idle 0:01:29, bytes 630, flags UfIOB\n' +
		'TCP OUTSIDE 98.196.168.156:58434 DMZ 192.168.100.81:443, idle 0:02:16, bytes 68472, flags UfIOB\n' +
		'TCP OUTSIDE 206.109.18.108:49475 DMZ 192.168.100.81:443, idle 0:01:39, bytes 5982, flags UfIOB\n' +
		'TCP OUTSIDE 70.113.1.116:51200 DMZ 192.168.100.81:443, idle 0:00:28, bytes 5059, flags UfIOB\n' +
		'TCP OUTSIDE 70.113.1.116:51201 DMZ 192.168.100.81:443, idle 0:00:27, bytes 4793, flags UfIOB\n' +
		'TCP OUTSIDE 70.113.1.116:51197 DMZ 192.168.100.81:443, idle 0:00:28, bytes 4793, flags UfIOB\n' +
		'TCP OUTSIDE 64.132.12.162:47908 DMZ 192.168.100.81:443, idle 0:02:09, bytes 364, flags UfrIOB\n' +
		'TCP OUTSIDE 98.196.168.156:58419 DMZ 192.168.100.81:443, idle 0:03:18, bytes 30070, flags UfIOB\n' +
		'TCP OUTSIDE 99.52.164.114:49369 DMZ 192.168.100.81:443, idle 0:03:28, bytes 218934, flags UIOB\n' +
		'TCP OUTSIDE 206.109.18.108:49386 DMZ 192.168.100.81:443, idle 0:01:09, bytes 6820, flags UfIOB\n' +
		'TCP OUTSIDE 206.109.18.108:49384 DMZ 192.168.100.81:443, idle 0:01:09, bytes 5690, flags UfIOB\n' +
		'TCP OUTSIDE 98.196.168.156:58392 DMZ 192.168.100.81:443, idle 0:03:56, bytes 68413, flags UfIOB\n' +
		'TCP OUTSIDE 70.120.163.129:54462 DMZ 192.168.100.81:443, idle 0:03:39, bytes 4649, flags UfrIOB\n' +
		'TCP OUTSIDE 70.120.163.129:54463 DMZ 192.168.100.81:443, idle 0:03:39, bytes 4649, flags UfrIOB\n' +
		'TCP OUTSIDE 70.120.163.129:54460 DMZ 192.168.100.81:443, idle 0:03:39, bytes 4649, flags UfrIOB\n' +
		'TCP OUTSIDE 70.120.163.129:54458 DMZ 192.168.100.81:443, idle 0:03:39, bytes 4649, flags UfrIOB\n' +
		'TCP OUTSIDE 70.195.197.68:11058 DMZ 192.168.100.81:443, idle 0:09:39, bytes 30046, flags UFRIOB\n' +
		'TCP OUTSIDE 208.92.228.62:41082 DMZ 192.168.100.81:443, idle 0:15:10, bytes 364, flags UfIOB\n' +
		'TCP OUTSIDE 208.92.228.62:41081 DMZ 192.168.100.81:443, idle 0:15:10, bytes 364, flags UfIOB\n' +
		'TCP OUTSIDE 208.92.228.62:41079 DMZ 192.168.100.81:443, idle 0:15:10, bytes 364, flags UfIOB\n' +
		'TCP OUTSIDE 208.92.228.62:41078 DMZ 192.168.100.81:443, idle 0:15:10, bytes 364, flags UfIOB\n' +
		'TCP OUTSIDE 208.92.228.62:41077 DMZ 192.168.100.81:443, idle 0:15:10, bytes 364, flags UfIOB\n' +
		'TCP OUTSIDE 72.191.129.237:50620 DMZ 192.168.100.81:443, idle 0:15:34, bytes 4645, flags UfIOB\n' +
		'TCP OUTSIDE 172.56.21.174:63051 DMZ 192.168.100.81:443, idle 0:17:03, bytes 0, flags UFB\n' +
		'TCP OUTSIDE 12.5.54.250:63961 DMZ 192.168.100.81:443, idle 0:21:09, bytes 10997, flags UfIOB\n' +
		'TCP OUTSIDE 12.5.54.250:62426 DMZ 192.168.100.81:443, idle 0:21:39, bytes 10997, flags UfIOB\n' +
		'TCP OUTSIDE 74.51.192.243:52206 DMZ 192.168.100.81:443, idle 0:26:07, bytes 4962, flags UfIOB\n' +
		'TCP OUTSIDE 174.126.164.96:62503 DMZ 192.168.100.81:443, idle 0:32:09, bytes 75880, flags UIOB\n' +
		'TCP OUTSIDE 67.140.127.89:52250 DMZ 192.168.100.81:443, idle 0:44:25, bytes 5349, flags UfIOB\n' +
		'TCP OUTSIDE 67.140.127.89:52247 DMZ 192.168.100.81:443, idle 0:46:58, bytes 57827, flags UIOB\n' +
		'TCP OUTSIDE 50.175.44.3:57511 DMZ 192.168.100.81:443, idle 0:53:47, bytes 536, flags UfIOB\n' +
		'UDP DMZ 192.168.100.69:161 INSIDE 172.24.12.28:62652, idle 0:00:05, bytes 300, flags -\n' +
		'UDP DMZ 192.168.100.69:161 INSIDE 172.24.12.28:63665, idle 0:00:35, bytes 88, flags -\n' +
		'UDP DMZ 192.168.100.69:161 INSIDE 172.24.12.28:50442, idle 0:00:50, bytes 17264, flags -\n' +
		'UDP DMZ 192.168.100.69:161 INSIDE 172.24.12.28:65426, idle 0:01:29, bytes 601, flags -\n' +
		'UDP DMZ 192.168.100.69:161 INSIDE 172.24.12.28:60388, idle 0:01:38, bytes 231, flags -\n' +
		'UDP DMZ 192.168.100.50:161 INSIDE 172.24.12.28:50442, idle 0:00:50, bytes 17246, flags -\n' +
		'UDP DMZ 192.168.100.50:161 INSIDE 172.24.12.28:57135, idle 0:00:59, bytes 600, flags -\n' +
		'UDP DMZ 192.168.100.50:161 INSIDE 172.24.12.28:63665, idle 0:01:02, bytes 88, flags -\n' +
		'UDP DMZ 192.168.100.50:161 INSIDE 172.24.12.28:65426, idle 0:01:11, bytes 231, flags -\n' +
		'UDP DMZ 192.168.100.50:161 INSIDE 172.24.12.28:51622, idle 0:01:16, bytes 300, flags -\n' +
		'UDP DMZ 192.168.100.58:161 INSIDE 172.24.12.28:60848, idle 0:00:02, bytes 229, flags -\n' +
		'UDP DMZ 192.168.100.58:161 INSIDE 172.24.12.28:62650, idle 0:00:26, bytes 590, flags -\n' +
		'UDP DMZ 192.168.100.58:161 INSIDE 172.24.12.28:63665, idle 0:00:54, bytes 88, flags -\n' +
		'UDP DMZ 192.168.100.58:161 INSIDE 172.24.12.28:51622, idle 0:01:13, bytes 300, flags -\n' +
		'TCP DMZ 192.168.100.58:3306 INSIDE 172.24.2.95:60084, idle 0:02:12, bytes 10160, flags UfFrIO\n' +
		'UDP DMZ 192.168.100.51:137 INSIDE 172.24.12.28:137, idle 0:01:35, bytes 7800, flags -\n' +
		'TCP OUTSIDE 172.56.15.7:27695 DMZ 192.168.100.71:443, idle 0:00:00, bytes 0, flags aB\n' +
		'TCP OUTSIDE 172.56.15.7:28399 DMZ 192.168.100.71:443, idle 0:00:00, bytes 0, flags aB\n' +
		'TCP OUTSIDE 5.196.30.81:56086 DMZ 192.168.100.71:443, idle 0:00:00, bytes 0, flags aB\n' +
		'TCP OUTSIDE 172.56.7.19:56052 DMZ 192.168.100.71:443, idle 0:00:00, bytes 0, flags aB\n' +
		'TCP OUTSIDE 172.56.15.7:46634 DMZ 192.168.100.71:443, idle 0:00:00, bytes 678, flags UIOB\n' +
		'TCP OUTSIDE 172.56.15.7:35823 DMZ 192.168.100.71:443, idle 0:00:00, bytes 678, flags UIOB\n' +
		'TCP OUTSIDE 209.253.154.178:51817 DMZ 192.168.100.71:443, idle 0:00:00, bytes 0, flags aB\n' +
		'TCP OUTSIDE 209.253.154.178:51816 DMZ 192.168.100.71:443, idle 0:00:00, bytes 0, flags aB\n' +
		'TCP OUTSIDE 172.56.15.7:62140 DMZ 192.168.100.71:443, idle 0:00:00, bytes 5499, flags UIOB\n' +
		'TCP OUTSIDE 172.56.15.7:19842 DMZ 192.168.100.71:443, idle 0:00:00, bytes 2986, flags UfIOB\n' +
		'TCP OUTSIDE 172.56.15.7:48086 DMZ 192.168.100.71:443, idle 0:00:00, bytes 1946, flags UfIOB\n' +
		'TCP OUTSIDE 172.56.15.7:39111 DMZ 192.168.100.71:443, idle 0:00:00, bytes 5499, flags UIOB\n' +
		'TCP OUTSIDE 172.56.15.7:19509 DMZ 192.168.100.71:443, idle 0:00:00, bytes 2778, flags UfIOB\n' +
		'TCP OUTSIDE 172.56.15.7:62418 DMZ 192.168.100.71:443, idle 0:00:00, bytes 6843, flags UIOB\n' +
		'TCP OUTSIDE 24.121.144.8:51475 DMZ 192.168.100.71:443, idle 0:00:00, bytes 4730, flags UIOB\n' +
		'TCP OUTSIDE 68.68.180.22:50196 DMZ 192.168.100.71:443, idle 0:00:01, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 76.183.103.1:51661 DMZ 192.168.100.71:443, idle 0:00:02, bytes 705, flags UIOB\n' +
		'TCP OUTSIDE 172.56.20.120:31525 DMZ 192.168.100.71:443, idle 0:00:02, bytes 0, flags UB\n' +
		'TCP OUTSIDE 204.115.6.185:59182 DMZ 192.168.100.71:443, idle 0:00:03, bytes 4526, flags UIOB\n' +
		'TCP OUTSIDE 204.115.6.185:54124 DMZ 192.168.100.71:443, idle 0:00:03, bytes 4526, flags UIOB\n' +
		'TCP OUTSIDE 128.177.161.179:41358 DMZ 192.168.100.71:443, idle 0:00:00, bytes 5995, flags UIOB\n' +
		'TCP OUTSIDE 172.56.7.68:50396 DMZ 192.168.100.71:443, idle 0:00:00, bytes 72829, flags UfIOB\n' +
		'TCP OUTSIDE 172.243.85.249:50322 DMZ 192.168.100.71:443, idle 0:00:04, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 172.243.85.249:50324 DMZ 192.168.100.71:443, idle 0:00:04, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 172.243.85.249:50325 DMZ 192.168.100.71:443, idle 0:00:04, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 172.243.85.249:50323 DMZ 192.168.100.71:443, idle 0:00:04, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 172.243.85.249:50320 DMZ 192.168.100.71:443, idle 0:00:04, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 108.239.218.167:53345 DMZ 192.168.100.71:443, idle 0:00:07, bytes 4494, flags UIOB\n' +
		'TCP OUTSIDE 132.3.53.81:31808 DMZ 192.168.100.71:443, idle 0:00:08, bytes 398, flags UIOB\n' +
		'TCP OUTSIDE 172.56.20.120:40028 DMZ 192.168.100.71:443, idle 0:00:09, bytes 0, flags UB\n' +
		'TCP OUTSIDE 172.56.7.19:35229 DMZ 192.168.100.71:443, idle 0:00:03, bytes 43339, flags UIOB\n' +
		'TCP OUTSIDE 76.127.23.198:62449 DMZ 192.168.100.71:443, idle 0:00:09, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 76.127.23.198:62448 DMZ 192.168.100.71:443, idle 0:00:09, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 76.127.23.198:62445 DMZ 192.168.100.71:443, idle 0:00:09, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 76.127.23.198:62446 DMZ 192.168.100.71:443, idle 0:00:09, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 76.127.23.198:62444 DMZ 192.168.100.71:443, idle 0:00:09, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 172.56.20.120:34998 DMZ 192.168.100.71:443, idle 0:00:09, bytes 0, flags UB\n' +
		'TCP OUTSIDE 172.56.20.120:45948 DMZ 192.168.100.71:443, idle 0:00:09, bytes 0, flags UB\n' +
		'TCP OUTSIDE 172.56.20.120:57039 DMZ 192.168.100.71:443, idle 0:00:01, bytes 0, flags aB\n' +
		'TCP OUTSIDE 66.87.96.85:21181 DMZ 192.168.100.71:443, idle 0:00:01, bytes 14891, flags UIOB\n' +
		'TCP OUTSIDE 66.87.96.85:5259 DMZ 192.168.100.71:443, idle 0:00:01, bytes 28476, flags UIOB\n' +
		'TCP OUTSIDE 76.184.103.223:51507 DMZ 192.168.100.71:443, idle 0:00:11, bytes 4655, flags UIOB\n' +
		'TCP OUTSIDE 66.87.121.5:10603 DMZ 192.168.100.71:443, idle 0:00:03, bytes 52623, flags UIOB\n' +
		'TCP OUTSIDE 66.87.121.5:6834 DMZ 192.168.100.71:443, idle 0:00:00, bytes 12539, flags UIOB\n' +
		'TCP OUTSIDE 66.87.121.5:16673 DMZ 192.168.100.71:443, idle 0:00:00, bytes 2364, flags UfIOB\n' +
		'TCP OUTSIDE 172.56.7.19:32261 DMZ 192.168.100.71:443, idle 0:00:03, bytes 50157, flags UIOB\n' +
		'TCP OUTSIDE 172.56.7.19:18818 DMZ 192.168.100.71:443, idle 0:00:06, bytes 32477, flags UIOB\n' +
		'TCP OUTSIDE 172.56.7.19:54443 DMZ 192.168.100.71:443, idle 0:00:07, bytes 32477, flags UIOB\n' +
		'TCP OUTSIDE 66.87.97.71:16266 DMZ 192.168.100.71:443, idle 0:00:00, bytes 210939, flags UIOB\n' +
		'TCP OUTSIDE 208.54.86.156:19993 DMZ 192.168.100.71:443, idle 0:00:27, bytes 532, flags UIOB\n' +
		'TCP OUTSIDE 64.132.12.162:11621 DMZ 192.168.100.71:443, idle 0:00:27, bytes 4458, flags UIOB\n' +
		'TCP OUTSIDE 108.90.113.128:6059 DMZ 192.168.100.71:443, idle 0:00:30, bytes 4665, flags UIOB\n' +
		'TCP OUTSIDE 172.56.20.120:23208 DMZ 192.168.100.71:443, idle 0:00:33, bytes 0, flags UB\n' +
		'TCP OUTSIDE 24.162.129.137:62300 DMZ 192.168.100.71:443, idle 0:00:34, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 108.209.2.222:50983 DMZ 192.168.100.71:443, idle 0:00:35, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 172.56.15.7:59312 DMZ 192.168.100.71:443, idle 0:00:09, bytes 51835, flags UIOB\n' +
		'TCP OUTSIDE 74.194.244.75:58029 DMZ 192.168.100.71:443, idle 0:00:00, bytes 32562, flags UIOB\n' +
		'TCP OUTSIDE 172.56.7.19:31688 DMZ 192.168.100.71:443, idle 0:00:05, bytes 96079, flags UfIOB\n' +
		'TCP OUTSIDE 172.56.20.120:44442 DMZ 192.168.100.71:443, idle 0:00:42, bytes 0, flags UB\n' +
		'TCP OUTSIDE 172.56.20.120:41436 DMZ 192.168.100.71:443, idle 0:00:05, bytes 19813, flags UfIOB\n' +
		'TCP OUTSIDE 172.56.20.120:27476 DMZ 192.168.100.71:443, idle 0:00:40, bytes 557, flags UIOB\n' +
		'TCP OUTSIDE 172.56.20.120:34853 DMZ 192.168.100.71:443, idle 0:00:42, bytes 0, flags UB\n' +
		'TCP OUTSIDE 172.56.20.120:45662 DMZ 192.168.100.71:443, idle 0:00:43, bytes 0, flags UB\n' +
		'TCP OUTSIDE 172.56.20.120:53275 DMZ 192.168.100.71:443, idle 0:00:01, bytes 37119, flags UIOB\n' +
		'TCP OUTSIDE 172.56.20.120:54825 DMZ 192.168.100.71:443, idle 0:00:40, bytes 557, flags UIOB\n' +
		'TCP OUTSIDE 172.56.20.120:26201 DMZ 192.168.100.71:443, idle 0:00:40, bytes 557, flags UIOB\n' +
		'TCP OUTSIDE 172.56.20.120:18114 DMZ 192.168.100.71:443, idle 0:00:41, bytes 557, flags UIOB\n' +
		'TCP OUTSIDE 76.185.17.85:62937 DMZ 192.168.100.71:443, idle 0:00:44, bytes 4645, flags UIOB\n' +
		'TCP OUTSIDE 70.113.96.11:49907 DMZ 192.168.100.71:443, idle 0:00:45, bytes 4649, flags UIOB\n' +
		'TCP OUTSIDE 172.56.21.92:56490 DMZ 192.168.100.71:443, idle 0:00:01, bytes 76812, flags UfFRIOB\n' +
		'TCP OUTSIDE 66.87.97.71:6366 DMZ 192.168.100.71:443, idle 0:00:29, bytes 21544, flags UfIOB\n' +
		'TCP OUTSIDE 72.178.53.195:50505 DMZ 192.168.100.71:443, idle 0:00:39, bytes 7154, flags UIOB\n' +
		'TCP OUTSIDE 75.148.155.205:19460 DMZ 192.168.100.71:443, idle 0:01:33, bytes 4695, flags UIOB\n' +
		'TCP OUTSIDE 199.115.187.115:54221 DMZ 192.168.100.71:443, idle 0:01:34, bytes 4645, flags UIOB\n' +
		'TCP OUTSIDE 74.194.244.75:57887 DMZ 192.168.100.71:443, idle 0:01:36, bytes 4462, flags UIOB\n' +
		'TCP OUTSIDE 209.119.180.158:55660 DMZ 192.168.100.71:443, idle 0:01:37, bytes 4462, flags UIOB\n' +
		'TCP OUTSIDE 162.71.241.254:37511 DMZ 192.168.100.71:443, idle 0:01:51, bytes 400, flags UIOB\n' +
		'TCP OUTSIDE 66.87.97.113:17995 DMZ 192.168.100.71:443, idle 0:01:16, bytes 35467, flags UIOB\n' +
		'TCP OUTSIDE 173.175.95.150:55659 DMZ 192.168.100.71:443, idle 0:00:39, bytes 536, flags UfrIOB\n' +
		'TCP OUTSIDE 66.87.97.113:27655 DMZ 192.168.100.71:443, idle 0:01:16, bytes 65259, flags UIOB\n' +
		'TCP OUTSIDE 72.178.53.195:50398 DMZ 192.168.100.71:443, idle 0:00:35, bytes 94891, flags UIOB\n' +
		'TCP OUTSIDE 72.178.53.195:50395 DMZ 192.168.100.71:443, idle 0:00:48, bytes 70402, flags UfIOB\n' +
		'TCP OUTSIDE 66.87.97.113:26438 DMZ 192.168.100.71:443, idle 0:02:08, bytes 4627, flags UFRIOB\n' +
		'TCP OUTSIDE 66.87.138.101:21610 DMZ 192.168.100.71:443, idle 0:03:43, bytes 202924, flags UfrIOB\n' +
		'TCP OUTSIDE 173.57.154.224:55783 DMZ 192.168.100.71:443, idle 0:02:50, bytes 135315, flags UfFRIOB\n' +
		'TCP OUTSIDE 45.17.238.144:49286 DMZ 192.168.100.71:443, idle 0:01:06, bytes 4825, flags UfIOB\n' +
		'TCP OUTSIDE 166.173.63.238:20226 DMZ 192.168.100.71:443, idle 0:04:17, bytes 108672, flags UfFRIOB\n' +
		'TCP OUTSIDE 66.87.120.209:18927 DMZ 192.168.100.71:443, idle 0:04:10, bytes 75431, flags UfFRIOB\n' +
		'TCP OUTSIDE 174.19.216.140:52887 DMZ 192.168.100.71:443, idle 0:03:39, bytes 400, flags UfrIOB\n' +
		'TCP OUTSIDE 184.79.228.252:51603 DMZ 192.168.100.71:443, idle 0:06:10, bytes 200139, flags UfrIOB\n' +
		'TCP OUTSIDE 97.44.65.215:4957 DMZ 192.168.100.71:443, idle 0:06:27, bytes 24435, flags UFRIOB\n' +
		'TCP OUTSIDE 70.115.54.111:55302 DMZ 192.168.100.71:443, idle 0:06:42, bytes 42650, flags UFRIOB\n' +
		'TCP OUTSIDE 66.87.99.35:15000 DMZ 192.168.100.71:443, idle 0:07:46, bytes 63389, flags UfrIOB\n' +
		'TCP OUTSIDE 66.87.99.35:1649 DMZ 192.168.100.71:443, idle 0:07:58, bytes 4332, flags UfrIOB\n' +
		'TCP OUTSIDE 207.119.7.80:49748 DMZ 192.168.100.71:443, idle 0:07:18, bytes 13953, flags UfIOB\n' +
		'TCP OUTSIDE 66.87.99.35:2645 DMZ 192.168.100.71:443, idle 0:08:29, bytes 60333, flags UfrIOB\n' +
		'TCP OUTSIDE 70.138.101.76:49251 DMZ 192.168.100.71:443, idle 0:05:32, bytes 4649, flags UfIOB\n' +
		'TCP OUTSIDE 70.138.101.76:49250 DMZ 192.168.100.71:443, idle 0:05:32, bytes 4649, flags UfIOB\n' +
		'TCP OUTSIDE 70.138.101.76:49248 DMZ 192.168.100.71:443, idle 0:05:32, bytes 4649, flags UfIOB\n' +
		'TCP OUTSIDE 70.138.101.76:49244 DMZ 192.168.100.71:443, idle 0:05:32, bytes 4649, flags UfIOB\n' +
		'TCP OUTSIDE 70.210.192.159:2379 DMZ 192.168.100.71:443, idle 0:08:47, bytes 7928, flags UfrIOB\n' +
		'TCP OUTSIDE 64.92.40.216:56380 DMZ 192.168.100.71:443, idle 0:06:39, bytes 749, flags UfIOB\n' +
		'TCP OUTSIDE 71.14.147.23:37726 DMZ 192.168.100.71:443, idle 0:06:36, bytes 0, flags UfB\n' +
		'TCP OUTSIDE 24.27.63.178:49626 DMZ 192.168.100.71:443, idle 0:09:05, bytes 4825, flags UfIOB\n' +
		'TCP OUTSIDE 70.138.101.76:58281 DMZ 192.168.100.71:443, idle 0:09:28, bytes 4825, flags UfIOB\n' +
		'TCP OUTSIDE 72.181.107.182:52142 DMZ 192.168.100.71:443, idle 0:14:06, bytes 4462, flags UfIOB\n' +
		'TCP OUTSIDE 216.4.56.141:8194 DMZ 192.168.100.71:443, idle 0:19:39, bytes 1339, flags UfIOB\n' +
		'TCP OUTSIDE 216.4.56.141:8192 DMZ 192.168.100.71:443, idle 0:20:25, bytes 28589, flags UIOB\n' +
		'TCP OUTSIDE 216.4.56.141:8190 DMZ 192.168.100.71:443, idle 0:20:29, bytes 63535, flags UfIOB\n' +
		'TCP OUTSIDE 97.77.166.182:60661 DMZ 192.168.100.71:443, idle 0:19:03, bytes 4462, flags UfIOB\n' +
		'TCP OUTSIDE 70.209.100.174:11293 DMZ 192.168.100.71:443, idle 0:21:10, bytes 200874, flags UfIOB\n' +
		'TCP OUTSIDE 73.206.208.37:49979 DMZ 192.168.100.71:443, idle 0:33:34, bytes 4494, flags UfIOB\n' +
		'TCP OUTSIDE 107.214.132.102:51276 DMZ 192.168.100.71:443, idle 0:36:36, bytes 4655, flags UfIOB\n' +
		'TCP OUTSIDE 107.214.132.102:51275 DMZ 192.168.100.71:443, idle 0:36:35, bytes 4655, flags UfIOB\n' +
		'TCP OUTSIDE 107.214.132.102:51273 DMZ 192.168.100.71:443, idle 0:36:56, bytes 4655, flags UfIOB\n' +
		'TCP OUTSIDE 107.214.132.102:51274 DMZ 192.168.100.71:443, idle 0:36:56, bytes 4655, flags UfIOB\n' +
		'TCP OUTSIDE 107.214.132.102:51272 DMZ 192.168.100.71:443, idle 0:37:11, bytes 4655, flags UfIOB\n' +
		'TCP OUTSIDE 107.214.132.102:51271 DMZ 192.168.100.71:443, idle 0:37:10, bytes 4655, flags UfIOB\n' +
		'TCP OUTSIDE 184.79.142.116:56772 DMZ 192.168.100.71:443, idle 0:40:34, bytes 8037, flags UIOB\n' +
		'TCP OUTSIDE 184.79.142.116:56770 DMZ 192.168.100.71:443, idle 0:40:52, bytes 8038, flags UIOB\n' +
		'TCP OUTSIDE 184.79.142.116:56769 DMZ 192.168.100.71:443, idle 0:40:31, bytes 8041, flags UIOB\n' +
		'TCP OUTSIDE 205.197.242.159:30230 DMZ 192.168.100.71:443, idle 0:41:52, bytes 24180, flags UfIOB\n' +
		'TCP OUTSIDE 205.197.242.159:20127 DMZ 192.168.100.71:443, idle 0:42:02, bytes 109298, flags UfIOB\n' +
		'TCP OUTSIDE 205.197.242.159:20120 DMZ 192.168.100.71:443, idle 0:42:15, bytes 76272, flags UfIOB\n' +
		'TCP OUTSIDE 162.225.10.49:53343 DMZ 192.168.100.71:443, idle 0:40:03, bytes 4649, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:30823 DMZ 192.168.100.71:443, idle 0:42:36, bytes 610, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:45926 DMZ 192.168.100.71:443, idle 0:42:35, bytes 610, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:7599 DMZ 192.168.100.71:443, idle 0:42:34, bytes 610, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:25962 DMZ 192.168.100.71:443, idle 0:44:35, bytes 24703, flags UIOB\n' +
		'TCP OUTSIDE 50.58.22.14:65109 DMZ 192.168.100.71:443, idle 0:44:34, bytes 22531, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:28741 DMZ 192.168.100.71:443, idle 0:42:34, bytes 661, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:37471 DMZ 192.168.100.71:443, idle 0:44:30, bytes 27399, flags UIOB\n' +
		'TCP OUTSIDE 50.58.22.14:48980 DMZ 192.168.100.71:443, idle 0:42:26, bytes 610, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:14569 DMZ 192.168.100.71:443, idle 0:44:35, bytes 31642, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:19947 DMZ 192.168.100.71:443, idle 0:42:23, bytes 610, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:54457 DMZ 192.168.100.71:443, idle 0:42:20, bytes 610, flags UfIOB\n' +
		'TCP OUTSIDE 50.58.22.14:49687 DMZ 192.168.100.71:443, idle 0:44:22, bytes 23259, flags UIOB\n' +
		'TCP OUTSIDE 63.175.184.254:63282 DMZ 192.168.100.71:443, idle 0:43:07, bytes 0, flags UfB\n' +
		'TCP OUTSIDE 63.175.184.254:63176 DMZ 192.168.100.71:443, idle 0:45:40, bytes 28673, flags UIOB\n' +
		'TCP OUTSIDE 70.209.103.119:3707 DMZ 192.168.100.71:443, idle 0:45:26, bytes 1864, flags UfIOB\n' +
		'TCP OUTSIDE 70.209.103.119:3683 DMZ 192.168.100.71:443, idle 0:45:49, bytes 2866, flags UfIOB\n' +
		'TCP OUTSIDE 172.56.21.154:37182 DMZ 192.168.100.71:443, idle 0:44:49, bytes 33486, flags UIOB\n' +
		'TCP OUTSIDE 172.56.21.154:62419 DMZ 192.168.100.71:443, idle 0:44:19, bytes 18614, flags UIOB\n' +
		'TCP OUTSIDE 172.56.21.154:45028 DMZ 192.168.100.71:443, idle 0:43:43, bytes 16490, flags UfIOB\n' +
		'TCP OUTSIDE 172.56.21.154:31913 DMZ 192.168.100.71:443, idle 0:43:29, bytes 77420, flags UfIOB\n' +
		'TCP OUTSIDE 70.117.137.93:62707 DMZ 192.168.100.71:443, idle 0:44:33, bytes 4649, flags UfIOB\n' +
		'TCP OUTSIDE 96.18.95.95:42081 DMZ 192.168.100.71:443, idle 0:47:50, bytes 21678, flags UIOB\n' +
		'TCP OUTSIDE 96.18.95.95:47341 DMZ 192.168.100.71:443, idle 0:47:51, bytes 25935, flags UIOB\n' +
		'TCP OUTSIDE 208.54.70.184:44900 DMZ 192.168.100.71:443, idle 0:49:18, bytes 656, flags UfIOB\n' +
		'TCP OUTSIDE 208.54.70.184:19754 DMZ 192.168.100.71:443, idle 0:48:41, bytes 656, flags UfIOB\n' +
		'TCP OUTSIDE 208.54.70.184:25769 DMZ 192.168.100.71:443, idle 0:48:32, bytes 656, flags UfIOB\n' +
		'TCP OUTSIDE 97.43.67.137:7134 DMZ 192.168.100.71:443, idle 0:51:46, bytes 9520, flags UfIOB\n' +
		'TCP OUTSIDE 97.43.67.137:7125 DMZ 192.168.100.71:443, idle 0:51:46, bytes 9520, flags UfIOB\n' +
		'TCP OUTSIDE 97.43.67.137:7116 DMZ 192.168.100.71:443, idle 0:51:46, bytes 8782, flags UfIOB\n' +
		'TCP OUTSIDE 184.79.149.36:53591 DMZ 192.168.100.71:443, idle 0:52:59, bytes 4825, flags UfIOB\n' +
		'TCP OUTSIDE 174.32.160.26:40593 DMZ 192.168.100.71:443, idle 0:55:21, bytes 4462, flags UfIOB\n' +
		'TCP OUTSIDE 72.0.39.72:52471 DMZ 192.168.100.71:443, idle 0:58:44, bytes 135750, flags UfIOB\n' +
		'TCP OUTSIDE 155.7.204.9:21318 DMZ 192.168.100.75:443, idle 0:00:03, bytes 363, flags UIOB\n' +
		'TCP OUTSIDE 76.73.131.31:49376 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49375 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49374 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49369 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49373 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49372 DMZ 192.168.100.75:80, idle 0:04:53, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49370 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49371 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49366 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49367 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49368 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49365 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49364 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 76.73.131.31:49363 DMZ 192.168.100.75:80, idle 0:04:54, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 70.122.83.87:59908 DMZ 192.168.100.75:80, idle 0:06:46, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 24.243.246.207:52088 DMZ 192.168.100.75:443, idle 0:06:40, bytes 87272, flags UfIOB\n' +
		'TCP OUTSIDE 24.243.246.207:52084 DMZ 192.168.100.75:80, idle 0:08:09, bytes 0, flags UfrB\n' +
		'TCP OUTSIDE 24.243.246.207:52056 DMZ 192.168.100.75:443, idle 0:09:37, bytes 4643, flags UfrIOB\n' +
		'TCP OUTSIDE 184.6.181.179:47819 DMZ 192.168.100.75:443, idle 0:51:11, bytes 72556, flags UIOB\n' +
		'UDP DMZ 192.168.100.53:137 INSIDE 172.24.12.28:137, idle 0:01:00, bytes 114750, flags -\n' +
		'TCP WIRELESS 10.96.140.79:35099 INSIDE 172.24.2.220:2901, idle 0:00:00, bytes 344, flags UIOB\n' +
		'TCP WIRELESS 10.96.140.154:46042 INSIDE 172.24.2.220:2901, idle 0:00:00, bytes 1007, flags UIOB\n' +
		'TCP WIRELESS 10.96.140.79:35098 INSIDE 172.24.2.220:2901, idle 0:00:00, bytes 1018, flags UIOB\n' +
		'TCP WIRELESS 10.96.140.79:35091 INSIDE 172.24.2.220:2901, idle 0:00:01, bytes 1052, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37702 INSIDE 172.24.2.220:2901, idle 0:00:01, bytes 973, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:35063 INSIDE 172.24.2.220:2901, idle 0:00:02, bytes 460, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:35055 INSIDE 172.24.2.220:2901, idle 0:00:00, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37684 INSIDE 172.24.2.220:2901, idle 0:00:03, bytes 620, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37675 INSIDE 172.24.2.220:2901, idle 0:00:04, bytes 1211, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.87:28229 INSIDE 172.24.2.220:2901, idle 0:00:05, bytes 556, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:35009 INSIDE 172.24.2.220:2901, idle 0:00:05, bytes 1704, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37653 INSIDE 172.24.2.220:2901, idle 0:00:07, bytes 4546, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34990 INSIDE 172.24.2.220:2901, idle 0:00:11, bytes 1129, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37645 INSIDE 172.24.2.220:2901, idle 0:00:12, bytes 547, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34967 INSIDE 172.24.2.220:2901, idle 0:00:01, bytes 1613, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34959 INSIDE 172.24.2.220:2901, idle 0:00:04, bytes 1141, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34957 INSIDE 172.24.2.220:2901, idle 0:00:04, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37621 INSIDE 172.24.2.220:2901, idle 0:00:05, bytes 3053, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37615 INSIDE 172.24.2.220:2901, idle 0:00:07, bytes 607, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34924 INSIDE 172.24.2.220:2901, idle 0:00:08, bytes 460, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37579 INSIDE 172.24.2.220:2901, idle 0:00:12, bytes 31854, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34865 INSIDE 172.24.2.220:2901, idle 0:00:17, bytes 1345, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:15104 INSIDE 172.24.2.220:2901, idle 0:00:01, bytes 1096, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34817 INSIDE 172.24.2.220:2901, idle 0:00:26, bytes 1133, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34793 INSIDE 172.24.2.220:2901, idle 0:00:04, bytes 554, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34792 INSIDE 172.24.2.220:2901, idle 0:00:01, bytes 1935, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34787 INSIDE 172.24.2.220:2901, idle 0:00:05, bytes 541, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37546 INSIDE 172.24.2.220:2902, idle 0:00:08, bytes 482, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34748 INSIDE 172.24.2.220:2901, idle 0:00:06, bytes 1641, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34705 INSIDE 172.24.2.220:2901, idle 0:00:15, bytes 484, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.87:28061 INSIDE 172.24.2.220:2901, idle 0:00:15, bytes 659, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34690 INSIDE 172.24.2.220:2901, idle 0:00:17, bytes 484, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34688 INSIDE 172.24.2.220:2901, idle 0:00:20, bytes 484, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34679 INSIDE 172.24.2.220:2901, idle 0:00:16, bytes 1979, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:15071 INSIDE 172.24.2.220:2901, idle 0:00:20, bytes 483, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34630 INSIDE 172.24.2.220:2901, idle 0:00:22, bytes 18652, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34623 INSIDE 172.24.2.220:2901, idle 0:00:20, bytes 3568, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37496 INSIDE 172.24.2.220:2901, idle 0:00:24, bytes 488, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34613 INSIDE 172.24.2.220:2901, idle 0:00:24, bytes 749, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34593 INSIDE 172.24.2.220:2901, idle 0:00:28, bytes 15017, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:15053 INSIDE 172.24.2.220:2901, idle 0:00:28, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37483 INSIDE 172.24.2.220:2901, idle 0:00:32, bytes 10087, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:15040 INSIDE 172.24.2.220:2901, idle 0:00:34, bytes 1173, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:15014 INSIDE 172.24.2.220:2901, idle 0:00:42, bytes 550, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34390 INSIDE 172.24.2.220:2901, idle 0:00:46, bytes 460, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:15002 INSIDE 172.24.2.220:2901, idle 0:00:46, bytes 1938, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:15000 INSIDE 172.24.2.220:2901, idle 0:00:47, bytes 600, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37454 INSIDE 172.24.2.220:2901, idle 0:00:47, bytes 557, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37451 INSIDE 172.24.2.220:2901, idle 0:00:46, bytes 14687, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34375 INSIDE 172.24.2.220:2901, idle 0:00:50, bytes 460, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34342 INSIDE 172.24.2.220:2901, idle 0:00:53, bytes 1110, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14973 INSIDE 172.24.2.220:2901, idle 0:00:57, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34295 INSIDE 172.24.2.220:2901, idle 0:00:57, bytes 2205, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37438 INSIDE 172.24.2.220:2901, idle 0:01:01, bytes 1111, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34251 INSIDE 172.24.2.220:2901, idle 0:01:08, bytes 488, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37419 INSIDE 172.24.2.220:2901, idle 0:01:05, bytes 1968, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34217 INSIDE 172.24.2.220:2901, idle 0:01:12, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34147 INSIDE 172.24.2.220:2901, idle 0:01:23, bytes 1102, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34136 INSIDE 172.24.2.220:2901, idle 0:01:24, bytes 1102, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34116 INSIDE 172.24.2.220:2902, idle 0:01:25, bytes 481, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34053 INSIDE 172.24.2.220:2901, idle 0:01:36, bytes 2803, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34052 INSIDE 172.24.2.220:2901, idle 0:01:36, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:34026 INSIDE 172.24.2.220:2901, idle 0:01:38, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33975 INSIDE 172.24.2.220:2901, idle 0:01:39, bytes 1574, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33968 INSIDE 172.24.2.220:2901, idle 0:01:43, bytes 1105, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14889 INSIDE 172.24.2.220:2901, idle 0:01:41, bytes 3221, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14886 INSIDE 172.24.2.220:2901, idle 0:01:50, bytes 482, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33924 INSIDE 172.24.2.220:2901, idle 0:01:50, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33892 INSIDE 172.24.2.220:2901, idle 0:01:50, bytes 1108, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14872 INSIDE 172.24.2.220:2901, idle 0:01:47, bytes 1187, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.87:27790 INSIDE 172.24.2.220:2901, idle 0:01:54, bytes 1121, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14857 INSIDE 172.24.2.220:2901, idle 0:01:53, bytes 558, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33793 INSIDE 172.24.2.220:2901, idle 0:02:01, bytes 460, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33768 INSIDE 172.24.2.220:2902, idle 0:02:06, bytes 1139, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14822 INSIDE 172.24.2.220:2901, idle 0:02:06, bytes 487, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33706 INSIDE 172.24.2.220:2901, idle 0:02:10, bytes 2528, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33686 INSIDE 172.24.2.220:2901, idle 0:02:13, bytes 1168, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33685 INSIDE 172.24.2.220:2901, idle 0:02:16, bytes 1590, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33613 INSIDE 172.24.2.220:2901, idle 0:02:24, bytes 1039, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33599 INSIDE 172.24.2.220:2901, idle 0:02:27, bytes 571, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14761 INSIDE 172.24.2.220:2901, idle 0:02:30, bytes 552, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33574 INSIDE 172.24.2.220:2901, idle 0:02:30, bytes 2584, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14757 INSIDE 172.24.2.220:2901, idle 0:02:31, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14756 INSIDE 172.24.2.220:2901, idle 0:02:31, bytes 1196, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.87:27710 INSIDE 172.24.2.220:2901, idle 0:02:37, bytes 1050, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37213 INSIDE 172.24.2.220:2901, idle 0:02:40, bytes 7708, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37197 INSIDE 172.24.2.220:2901, idle 0:02:39, bytes 15964, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33453 INSIDE 172.24.2.220:2901, idle 0:02:50, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33447 INSIDE 172.24.2.220:2901, idle 0:02:48, bytes 3233, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33394 INSIDE 172.24.2.220:2901, idle 0:02:55, bytes 1040, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14699 INSIDE 172.24.2.220:2901, idle 0:02:59, bytes 554, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33348 INSIDE 172.24.2.220:2901, idle 0:03:03, bytes 1072, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33322 INSIDE 172.24.2.220:2901, idle 0:03:08, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14657 INSIDE 172.24.2.220:2901, idle 0:03:23, bytes 20607, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14656 INSIDE 172.24.2.220:2901, idle 0:03:23, bytes 2240, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33204 INSIDE 172.24.2.220:2902, idle 0:03:26, bytes 489, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14639 INSIDE 172.24.2.220:2901, idle 0:03:28, bytes 561, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33147 INSIDE 172.24.2.220:2901, idle 0:03:30, bytes 13321, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33140 INSIDE 172.24.2.220:2901, idle 0:03:34, bytes 452, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33132 INSIDE 172.24.2.220:2901, idle 0:03:33, bytes 1031, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14607 INSIDE 172.24.2.220:2901, idle 0:03:38, bytes 1155, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33129 INSIDE 172.24.2.220:2901, idle 0:03:37, bytes 2280, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33119 INSIDE 172.24.2.220:2901, idle 0:03:37, bytes 4671, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37058 INSIDE 172.24.2.220:2901, idle 0:03:40, bytes 476, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14598 INSIDE 172.24.2.220:2901, idle 0:03:40, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.87:27547 INSIDE 172.24.2.220:2901, idle 0:03:39, bytes 1355, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14586 INSIDE 172.24.2.220:2901, idle 0:03:44, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33082 INSIDE 172.24.2.220:2901, idle 0:03:48, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:37039 INSIDE 172.24.2.220:2901, idle 0:03:46, bytes 24483, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33052 INSIDE 172.24.2.220:2901, idle 0:03:48, bytes 3474, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:33037 INSIDE 172.24.2.220:2901, idle 0:03:54, bytes 1079, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32930 INSIDE 172.24.2.220:2901, idle 0:04:06, bytes 24221, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32922 INSIDE 172.24.2.220:2901, idle 0:04:07, bytes 476, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32914 INSIDE 172.24.2.220:2901, idle 0:04:08, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14410 INSIDE 172.24.2.220:2901, idle 0:04:20, bytes 590, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14401 INSIDE 172.24.2.220:2901, idle 0:04:28, bytes 481, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:36917 INSIDE 172.24.2.220:2901, idle 0:04:33, bytes 1174, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14379 INSIDE 172.24.2.220:2901, idle 0:04:32, bytes 1235, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32762 INSIDE 172.24.2.220:2901, idle 0:04:36, bytes 1125, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32741 INSIDE 172.24.2.220:2901, idle 0:04:41, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32732 INSIDE 172.24.2.220:2901, idle 0:04:42, bytes 20951, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:36855 INSIDE 172.24.2.220:2901, idle 0:04:52, bytes 485, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32680 INSIDE 172.24.2.220:2901, idle 0:04:53, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32666 INSIDE 172.24.2.220:2901, idle 0:04:55, bytes 1161, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32662 INSIDE 172.24.2.220:2901, idle 0:04:55, bytes 562, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32641 INSIDE 172.24.2.220:2901, idle 0:04:54, bytes 1151, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32613 INSIDE 172.24.2.220:2901, idle 0:05:00, bytes 1119, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32575 INSIDE 172.24.2.220:2901, idle 0:05:01, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32534 INSIDE 172.24.2.220:2901, idle 0:05:08, bytes 748, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:36786 INSIDE 172.24.2.220:2901, idle 0:05:06, bytes 1136, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:36783 INSIDE 172.24.2.220:2902, idle 0:05:09, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14266 INSIDE 172.24.2.220:2901, idle 0:05:19, bytes 1157, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32408 INSIDE 172.24.2.220:2901, idle 0:05:20, bytes 1177, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14256 INSIDE 172.24.2.220:2901, idle 0:05:27, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32329 INSIDE 172.24.2.220:2901, idle 0:05:28, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14223 INSIDE 172.24.2.220:2901, idle 0:05:30, bytes 1933, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14213 INSIDE 172.24.2.220:2901, idle 0:05:35, bytes 1137, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.87:27281 INSIDE 172.24.2.220:2901, idle 0:05:35, bytes 482, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32259 INSIDE 172.24.2.220:2901, idle 0:05:36, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14206 INSIDE 172.24.2.220:2901, idle 0:05:34, bytes 538, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.87:27256 INSIDE 172.24.2.220:2901, idle 0:05:39, bytes 1357, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14199 INSIDE 172.24.2.220:2901, idle 0:05:39, bytes 14683, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32170 INSIDE 172.24.2.220:2901, idle 0:05:47, bytes 537, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32148 INSIDE 172.24.2.220:2901, idle 0:05:49, bytes 1136, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14182 INSIDE 172.24.2.220:2901, idle 0:05:55, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32126 INSIDE 172.24.2.220:2901, idle 0:05:53, bytes 1091, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32107 INSIDE 172.24.2.220:2901, idle 0:05:54, bytes 1173, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32101 INSIDE 172.24.2.220:2901, idle 0:05:58, bytes 537, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14148 INSIDE 172.24.2.220:2901, idle 0:05:55, bytes 1095, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14146 INSIDE 172.24.2.220:2901, idle 0:05:59, bytes 541, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:36639 INSIDE 172.24.2.220:2901, idle 0:06:01, bytes 3453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:36631 INSIDE 172.24.2.220:2901, idle 0:06:02, bytes 1103, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32061 INSIDE 172.24.2.220:2901, idle 0:06:04, bytes 491, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:32015 INSIDE 172.24.2.220:2901, idle 0:06:16, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31994 INSIDE 172.24.2.220:2901, idle 0:06:18, bytes 1894, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.87:27172 INSIDE 172.24.2.220:2901, idle 0:06:19, bytes 1151, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:14049 INSIDE 172.24.2.220:2901, idle 0:06:25, bytes 545, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31919 INSIDE 172.24.2.220:2901, idle 0:06:28, bytes 630, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31837 INSIDE 172.24.2.220:2901, idle 0:06:33, bytes 460, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31777 INSIDE 172.24.2.220:2901, idle 0:06:37, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31752 INSIDE 172.24.2.220:2901, idle 0:06:39, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31722 INSIDE 172.24.2.220:2901, idle 0:06:41, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31714 INSIDE 172.24.2.220:2901, idle 0:06:42, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31637 INSIDE 172.24.2.220:2901, idle 0:06:51, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:36532 INSIDE 172.24.2.220:2901, idle 0:06:50, bytes 1638, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:13948 INSIDE 172.24.2.220:2901, idle 0:06:47, bytes 1146, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:13939 INSIDE 172.24.2.220:2901, idle 0:06:52, bytes 1125, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:13933 INSIDE 172.24.2.220:2901, idle 0:06:54, bytes 476, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31559 INSIDE 172.24.2.220:2901, idle 0:06:51, bytes 453, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:13920 INSIDE 172.24.2.220:2902, idle 0:06:57, bytes 489, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.84:36501 INSIDE 172.24.2.220:2901, idle 0:06:58, bytes 485, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31471 INSIDE 172.24.2.220:2901, idle 0:07:01, bytes 1296, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31446 INSIDE 172.24.2.220:2902, idle 0:07:02, bytes 1148, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31430 INSIDE 172.24.2.220:2901, idle 0:07:00, bytes 1174, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31387 INSIDE 172.24.2.220:2901, idle 0:07:03, bytes 1868, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31344 INSIDE 172.24.2.220:2901, idle 0:07:09, bytes 488, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.87:27052 INSIDE 172.24.2.220:2901, idle 0:07:09, bytes 614, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31338 INSIDE 172.24.2.220:2901, idle 0:07:10, bytes 1268, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31331 INSIDE 172.24.2.220:2901, idle 0:07:10, bytes 482, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31264 INSIDE 172.24.2.220:2901, idle 0:07:18, bytes 1273, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.85:13857 INSIDE 172.24.2.220:2901, idle 0:07:16, bytes 1300, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31186 INSIDE 172.24.2.220:2901, idle 0:07:20, bytes 544, flags UfFrIOB\n' +
		'TCP WIRELESS 10.96.140.79:31137 INSIDE 172.24.2.220:2901, idle 0:07:24, bytes 1338, flags UfFrIOB\n';
		$('#showconninput').val(demodata);

	});
		
	function getSortedKeys(obj) {
	    var keys = []; for(var key in obj) keys.push(key);
	    return keys.sort(function(a,b){return obj[a]-obj[b]});
	}
});