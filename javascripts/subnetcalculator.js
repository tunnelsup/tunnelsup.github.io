/*************************************************** 
    Subnetting tool created exclusively by TunnelsUp for TunnelsUp. 
    All right reserved. Redistribution of this code is prohibited 
    without permission from TunnelsUp
    Copyright 2015
 **************************************************/

// Declare a few globals
var networkIP = "";
var broadcastIP = "";
var usableFirst = "";
var usableLast = "";
var inputIP;
var inputMask;
var inputSubSubnet = "";
var highlightHosts = "";
var requiredHosts = "";
var wildcardMask;
var finalNetmask;
var maskType;
var ipType;
 $(document).ready(function() {
	$("#calculate").click(function(){
       	// reset vars
       	$(".errorMessage").html("");
       	$(".results").html("");
       	networkIP = "";
       	broadcastIP = "";
		usableFirst = "";
		usableLast = "";
		highlightHosts = "";
		requiredHosts = "";
		wildcardMask = "";
		finalNetmask = "";
		maskType = "";
		ipType = "";
		inputSubSubnet = "";

	    var input = document.subnet.ip.value;
	    tokenize(input);
	    ipType = findIPType(inputIP);
	    if (ipType == "invalid") {
	        $(".errorMessage").html("Invalid IP address.");
	        return;
	    } else if (ipType == "ipv4") {
	        // verify IP and netmask are valid!
			if (inputMask == null) {
				$(".errorMessage").html("Invalid hosts requirement or missing netmask. Valid number of hosts is from 2-65,000.");
				return;	
			}
			if (verifyWildcard(inputMask) == true) {
				maskType = "wildcard";
				convertWildcardToNetmask(inputMask);
				inputMask = finalNetmask;
			}
			var verifyMaskResults = verifyMask(inputMask);
			if (verifyMaskResults != true) {
	        	$(".errorMessage").html("Invalid mask. See examples for possible values.");
	        	return;
			}

			// Calculate netmasks
			if (isMaskCIDR(inputMask)) {
				maskType = "cidr";
				CIDRMask = inputMask;
				finalNetmask = convertCIDRtoNetmask(inputMask);
			} else {
				if (maskType == "") {maskType = "netmask";}
				finalNetmask = inputMask;
				CIDRMask = convertNetmaskToCIDR(inputMask);
			}

			if (maskType == "wildcard") {
				_gaq.push(['_trackEvent', 'Subnet Calculator', 'Mask Wildcard', 'Calculated',, false]);
			} else if (maskType == "cidr") {
				_gaq.push(['_trackEvent', 'Subnet Calculator', 'Mask CIDR', 'Calculated',, false]);
			} else if (maskType == "netmask") {
				_gaq.push(['_trackEvent', 'Subnet Calculator', 'Mask Netmask', 'Calculated',, false]);
			} else if (maskType == "reverse") {
				_gaq.push(['_trackEvent', 'Subnet Calculator', 'Mask Reverse', 'Calculated',, false]);
			}

			var binaryMask = "";
			var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
			var netmaskArray = finalNetmask.match(ipPattern);
			for (i = 1; i < 5; i++) {
				thisSegment = parseInt(netmaskArray[i]);
				if (thisSegment == 0) {
					binaryMask = binaryMask + "00000000";
				} else {
					binaryMask = binaryMask + thisSegment.toString(2);
				}
				if (i < 4) binaryMask = binaryMask + ".";
			}

			// calculate the class of this network
			var classOfNetwork = determineClass(inputIP);

			// calculate number of hosts int his network
			var numberOfHosts = Math.pow(2, (32 -CIDRMask));
			var usableHosts = numberOfHosts - 2;

			// calculate wildcard mask
			convertNetmaskToWildcard(finalNetmask);

			// calculate the network begin and end
			determineNetworkAddress(inputIP, finalNetmask);

			// masks of 31 and 32 don't have usable IPs
			if (CIDRMask > 30) {
				usableFirst = "N/A";
				usableLast = "N/A";
			}
			var output = '<table class="table table-striped table-hover">' +
			'<tr><td><strong>IP Address:</strong></td><td>' + inputIP + '</td></tr>' +
			'<tr><td><strong>Netmask:</strong></td><td>' + finalNetmask + '</td></tr>' +
			'<tr><td><strong>Wildcard Mask:</strong></td><td>' + wildcardMask + '</td></tr>' +
			'<tr><td><strong>CIDR Notation:</strong></td><td>/' + CIDRMask + '</td></tr>' +
			'<tr><td><strong>Network Address:</strong></td><td>' + networkIP + '</td></tr>' +
			'<tr class="info"><td><strong>Usable Host Range:</strong></td><td>' + usableFirst + ' - ' + usableLast + '</td></tr>' +
			'<tr><td><strong>Broadcast Address:</strong></td><td>' + broadcastIP + '</td></tr>' +
			'<tr><td><strong>Binary Netmask:</strong></td><td>' + binaryMask + '</td></tr>' +
			'<tr><td><strong>Total number of hosts:</strong></td><td>' + addCommas(numberOfHosts) + '</td></tr>' +
			'<tr class="' + highlightHosts + '"><td><strong>Number of usable hosts:</strong></td><td>' + addCommas(usableHosts) + requiredHosts + '</td></tr>' +
			'<tr><td><strong>IP Class:</strong></td><td>' + classOfNetwork + '</td></tr>' +
			'<tr><td><strong>Move to adjacent network</strong></td><td><button class="button netprev" type="button"><i class="icon-arrow-left"></i> Backward</button> &nbsp; <button class="button netnext" type="button">Forward <i class="icon-arrow-right"></i></button></td></tr>' +
			'</table>';

			_gaq.push(['_trackEvent', 'Subnet Calculator', 'Calculate IPv4', 'Clicked',, false]);

		} else if (ipType == "ipv6") {
			//******************************************
			//********* PROCESS IPV6 INPUT
			//******************************************
			if (inputMask == undefined) {
				inputMask = "128";
			}
			if (!isMaskIPV6CIDR(inputMask)) {
		        $(".errorMessage").html("Improper CIDR notation. Values can be /1 - /128.");
		        return;
			}			 
			if (inputSubSubnet != "") {
				if (!isSubSubMaskIPV6CIDR(inputSubSubnet)) {
			        $(".errorMessage").html("Improper sub network defined. Value must greater than network prefix and less than /128.");
			        return;
				}	
			}
			var numberOfHosts = "";
			inputIP = reformatTrailingIPV4(inputIP);
			inputIP = inputIP.toUpperCase();
			var longestIPV6 = formatIPV6Longest(inputIP);
			var shortestIPV6 = formatipv6preferred(inputIP);
			var totalHosts = Math.pow(2, (128 - inputMask));
			totalHosts = convertScientificNotationToFixed(totalHosts);
			var prefixAddress = findIPV6PrefixAddress(inputMask);
			var subnetPrefix = findIPV6SubnetPrefix(prefixAddress,longestIPV6);
			var lastHost = findIPV6LastHost(prefixAddress, subnetPrefix, longestIPV6);

			var totalPercent = totalHosts / 340282366920938463463374607431768211456;
			totalPercent = totalPercent * 100;
			if (inputMask > 26) { totalPercent = "< 0.0000001"; }

			var output = '<table class="table table-striped table-hover">' +
			'<tr><td><strong>Expanded Notation:</strong></td><td>' + longestIPV6 + '</td></tr>' +
			'<tr><td><strong>Condensed Notation:</strong></td><td>' + shortestIPV6.toUpperCase() + '</td></tr>' +
			'<tr><td><strong>Prefix Length:</strong></td><td>' + inputMask + '</td></tr>' +
			'<tr><td><strong>Network Prefix with Mask:</strong></td><td>' + subnetPrefix + '</td></tr>' +
			'<tr><td><strong>Prefix Address:</strong></td><td>' + prefixAddress + '</td></tr>' +
			'<tr class="info"><td><strong>Host Range:</strong></td><td>' + subnetPrefix + ' -<br>' + lastHost + '</td></tr>' +
			'<tr><td><strong>Total number of hosts:</strong></td><td>' + addCommas(totalHosts) + '</td></tr>' +
			'<tr><td><strong>% of total IPv6 Pool:</strong></td><td>' + totalPercent + '%</td></tr>';
			if (inputSubSubnet != "") {
				output = output + '<tr class="warning"><td><strong>Subnetwork Prefix:</strong></td><td>' + inputSubSubnet + '</td></tr>';
				var numOfSubnets = Math.pow(2, (inputSubSubnet - inputMask));
				numOfSubnets = convertScientificNotationToFixed(numOfSubnets);
				output = output + '<tr class="warning"><td><strong>Number of Subnets in Network:</strong></td><td>' + addCommas(numOfSubnets) + '</td></tr>';
				
				var subPrefixAddress = findIPV6PrefixAddress(inputSubSubnet);
				var subnettedPrefix = findIPV6SubnettedPrefix(subPrefixAddress, prefixAddress, longestIPV6);
				var totalHostsOfSubnet = Math.pow(2, (128 - inputSubSubnet));
				totalHostsOfSubnet = convertScientificNotationToFixed(totalHostsOfSubnet);
				output = output + '<tr class="warning"><td><strong>Number of Hosts in Network:</strong></td><td>' + addCommas(totalHostsOfSubnet) + '</td></tr>';
				output = output + '<tr class="warning"><td><strong>Subnet Prefix Subnetted:</strong></td><td>' + subnettedPrefix + '</td></tr>';

			}
			output = output + '</table>';
			
			_gaq.push(['_trackEvent', 'Subnet Calculator', 'Calculate IPv6', 'Calculated',, false]);

	        //$(".errorMessage").html("IPV6 not supported yet");
	        //return;
		}

        $("#results").html(output);

        // $('html, body').animate({
        //     scrollTop: $("#inputHead").offset().top
        // }, 500);
  	});
 	
	// Deal with URL parameters
 	var get = [];
    get.ip = getUrlVars()["ip"];
    if (get.ip !== undefined) {
    	get.ip = get.ip.replace(/%20/gi, " ");
    	get.ip = get.ip.replace(/%2F/gi, "/");
    	get.ip = get.ip.replace(/%3A/gi, ":");
    	get.ip = get.ip.replace(/%23/gi, "#");
    	get.ip = get.ip.replace(/\+/gi, " ");
    	document.subnet.ip.value = get.ip;
    	$("#calculate").trigger("click");
    }


	// valid inputs:
	// 192.168.1.1/24
	// 192.168.1.1 255.255.255.0
	// 192.168.1.1 #100   (indicates a network that needs 100 hosts)
	// 192.168.1.1 0.0.0.256
	function tokenize(input) {
		// remove all forward slashes
	    input = input.replace(/\//g," ");
	    // remove all whitespaces thare are 2+ or in the beginning or end of input
	    input = trim(input);
	    // split the arguments at 3 the space
	    var inputArray = input.split(" ");
	    inputIP = inputArray[0];
	    inputMask = inputArray[1];
	    if (inputArray.length > 2) {
	    	inputSubSubnet = inputArray[2];
	    }
	    if (inputMask != null) {
		    if (inputMask.match(/^#/)) {
		    	maskType = "reverse";
		    	inputMask = findMaskFromHosts(inputMask);
		    }
	    }
	}

	// **************** below is ipv6 code

	function findIPV6SubnettedPrefix(subPrefixAddress, prefixAddress, longestIPV6){
		var returnIP = "";
		for (i = 0; i < subPrefixAddress.length; i++) {
			if (subPrefixAddress.charAt(i) == ":") {
				returnIP = returnIP + ":"; 
			} else if ((subPrefixAddress.charAt(i) == "F") && (prefixAddress.charAt(i) == "F")) {
				returnIP = returnIP + longestIPV6.charAt(i);
			} else if ((subPrefixAddress.charAt(i) == "F") && (prefixAddress.charAt(i) == "0")) {
				returnIP = returnIP + '<strong>s</strong>';
			} else if ((subPrefixAddress.charAt(i) == "0") && (prefixAddress.charAt(i) == "0")) {
				returnIP = returnIP + 'h';
			} else {
				returnIP = returnIP + "?";
			}
		}
		return returnIP;
	}

	function findIPV6SubnetPrefix(subnetPrefix,longestIPV6) {
		var returnIP = "";
		for (i = 0; i < subnetPrefix.length; i++) {
			if (subnetPrefix.charAt(i) == ":") {
				returnIP = returnIP + ":"; 
			} else if (subnetPrefix.charAt(i) == "F") {
				returnIP = returnIP + longestIPV6.charAt(i);
			} else if (subnetPrefix.charAt(i) == "E") {  // 1110
				var hexA = 0xE;
				var hexB = parseInt(longestIPV6.charAt(i), 16);  // convert string to hex value
				var hexResult = hexA & hexB;
				hexResult = hexResult.toString(16);   // convert decimal to hex
				returnIP = returnIP + hexResult.toUpperCase();
			} else if (subnetPrefix.charAt(i) == "C") {  // 1100
				var hexA = 0xC;
				var hexB = parseInt(longestIPV6.charAt(i), 16);  // convert string to hex value
				var hexResult = hexA & hexB;
				hexResult = hexResult.toString(16);   // convert decimal to hex
				returnIP = returnIP + hexResult.toUpperCase();
			} else if (subnetPrefix.charAt(i) == "8") {  // 1000
				var hexA = 0x8;
				var hexB = parseInt(longestIPV6.charAt(i), 16);  // convert string to hex value
				var hexResult = hexA & hexB;
				hexResult = hexResult.toString(16);   // convert decimal to hex
				returnIP = returnIP + hexResult.toUpperCase();
			} else if (subnetPrefix.charAt(i) == "0") {
				returnIP = returnIP + "0";
			}
		}
		return returnIP;
	}

	function findIPV6LastHost(prefixAddress, subnetPrefix, longestIPV6) {
		var returnIP = "";
		for (i = 0; i < prefixAddress.length; i++) {
			if (prefixAddress.charAt(i) == ":") {
				returnIP = returnIP + ":"; 
			} else if (prefixAddress.charAt(i) == "F") {
				returnIP = returnIP + longestIPV6.charAt(i);
			} else if (prefixAddress.charAt(i) == "E") {  // 1110
				var hexA = parseInt(subnetPrefix.charAt(i),16);
				var thisVal = hexA + 0x01;
				returnIP = returnIP + thisVal.toString(16).toUpperCase();
			} else if (prefixAddress.charAt(i) == "C") {  // 1100
				var hexA = parseInt(subnetPrefix.charAt(i),16);
				var thisVal = hexA + 0x03;
				returnIP = returnIP + thisVal.toString(16).toUpperCase();
			} else if (prefixAddress.charAt(i) == "8") {  // 1000
				var hexA = parseInt(subnetPrefix.charAt(i),16);
				var thisVal = hexA + 0x07;
				returnIP = returnIP + thisVal.toString(16).toUpperCase();
			} else if (prefixAddress.charAt(i) == "0") {
				returnIP = returnIP + "F";
			}
		}
		return returnIP;
	}

	function findIPV6PrefixAddress(inputMask) {
		var bits = inputMask;
		var binaryMask = "";
		var hexMask = "";
		for (i = 1; i < 129; i++) {
			if (i <= bits) {
				binaryMask = binaryMask + "1";
			} else {
				binaryMask = binaryMask + "0";
			}
			if ((i % 4) == 0) {
				binaryMask = binaryMask + ":";
			}
		}
		var binaryMaskArray = binaryMask.split(":");
		for (i = 0; i < binaryMaskArray.length; i++) {
			if (binaryMaskArray[i] == "0000") {
				hexMask = hexMask + "0";
			} else if (binaryMaskArray[i] == "1000") {
				hexMask = hexMask + "8";
			} else if (binaryMaskArray[i] == "1100") {
				hexMask = hexMask + "C";
			} else if (binaryMaskArray[i] == "1110") {
				hexMask = hexMask + "E";
			} else if (binaryMaskArray[i] == "1111") {
				hexMask = hexMask + "F";
			} 	
			var j = i + 1;
			if (i < (binaryMaskArray.length - 2)) {
				if ((j % 4) == 0) {
					hexMask = hexMask + ":";
				}
			}
		}
		return hexMask;
	}

	function convertScientificNotationToFixed(x) {
	  if (Math.abs(x) < 1.0) {
	    var e = parseInt(x.toString().split('e-')[1]);
	    if (e) {
	        x *= Math.pow(10,e-1);
	        x = '0.' + (new Array(e)).join('0') + x.toString().substring(2);
	    }
	  } else {
	    var e = parseInt(x.toString().split('+')[1]);
	    if (e > 20) {
	        e -= 20;
	        x /= Math.pow(10,e);
	        x += (new Array(e+1)).join('0');
	    }
	  }
	  return x;
	}

	// some valid IPv6 addresses have a trailing IPv4 address. Convert these to hex. ::1.2.223.224/96
	function reformatTrailingIPV4(thisIP){
		var newIP = "";
		var IPV6Array = thisIP.split(":");
		var returnIP = "";

		for (i = 0; i < IPV6Array.length; i++) {
			if (i < IPV6Array.length - 1) {
				newIP = newIP + IPV6Array[i] + ":";
			} else {
				var thisSegment = IPV6Array[i];
				if (verifyIP(thisSegment) == true) { // If the number is an IPv4 number inside an IPv6 number, we need to convert it to hex.
					var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
					var ipArray = thisSegment.match(ipPattern);
					var thisNewSegment = "";
					for (j = 1; j < 5; j++) {
						var thisDecValue = parseInt(ipArray[j]);
						var thisHexValue = thisDecValue.toString(16);
						if (thisHexValue.length < 2) { thisHexValue = "0" + thisHexValue; }
						thisNewSegment = thisNewSegment + thisHexValue;
						if (j == 2) {
							thisNewSegment = thisNewSegment + ":";
						}
					}
					newIP = newIP + thisNewSegment;
				} else {
					newIP = newIP + IPV6Array[i];

				}
			}

		}		
		return newIP;
	}

	function formatIPV6Longest(thisIP) {
		var IPV6Array = thisIP.split(":");
		var returnIP = "";

		// loop through every segment (the numbers between each colon)
		for (i = 0; i < IPV6Array.length; i++) {
			if (IPV6Array[i] == "") {  // if we don't have a number in between the colon
				var j = i + 1;
				if (i == 0) {   // expand the blank number before the first colon
					returnIP = returnIP + "0000";
				} else if (j == IPV6Array.length) {   // expand the blank number after the last colon
					returnIP = returnIP + "0000";
				} else {
					// dealing with a double colon ::
					var fillin = 9 - IPV6Array.length;
					for (j = 0; j < fillin; j++){
						returnIP = returnIP + "0000";
						if (j < (fillin - 1)) { returnIP = returnIP + ":"; }
					}
				}
			} else if (IPV6Array[i].length == 1 ) {
				returnIP = returnIP + "000" + IPV6Array[i];
			} else if (IPV6Array[i].length == 2 ) {
				returnIP = returnIP + "00" + IPV6Array[i];
			} else if (IPV6Array[i].length == 3 ) {
				returnIP = returnIP + "0" + IPV6Array[i];
			} else {
				returnIP = returnIP + IPV6Array[i];
			}			
			if (i < (IPV6Array.length - 1)) { returnIP = returnIP + ":"; }
		}
		return returnIP;
	}

	function formatipv6preferred(thisIP) {
		var resultstr = "";
		var beststr = "";

		beststr = formatbestipv6(thisIP);	

		resultstr = resultstr + "" + beststr;
		return resultstr;
	}

	function formatbestipv6(thisIP){
		var str;
		var beststr = "Not a valid IPv6 Address";
		var segments;
		var totalv6segments;

		// ASSERT: thisIP is now a well-formed IPv6 address, as a result of the checkipv6() call above
		// Make the string lowercase and split it up on the ":"
		str = thisIP.toLowerCase();
		segments = str.split(":");

		// ASSERT: the 'segments' array contains the segments of the address after splitting on ":"
		// Trim off leading or trailing double-:: from front or back (:: or ::a:b:c... or ...a:b:c::)
		trimcolonsfromends(segments);
		// ASSERT: segments[] has exactly zero or one "" string that marks the position of the "::"

		// Find the empty segment (if any) resulting from "::"
		// Fill it with enough "0000" segments to make a total of 8 segments
		fillemptysegment(segments);
		// ASSERT: All non-empty entry have been expanded as necessary; if IPv4 address present, only 7 segments

		// Now strip off leading zero's from all segments
		stripleadingzeroes(segments);

		// Scan through looking for consecutive "0" segments
		removeconsecutivezeroes(segments);

		// Assemble best representation from remainder of segments
		beststr = assemblebestrepresentation(segments);

		
		return beststr;
	}

	function trimcolonsfromends(segments){
		var seglen = segments.length;
		if ((segments[0] == '') && (segments[1] == '') && (segments[2] == "")) // must have been "::"
		{ segments.shift(); segments.shift() }	// remove first two items
		// leaving a single segment of ""
		else if ((segments[0] == '') && (segments[1] == ''))	// must have been ::xxxx...
		{ segments.shift(); }	// remove the first item
		else if ((segments[seglen-1] == '') && (segments[seglen-2] == '')) // must have been xxxx::
		{ segments.pop(); }	// remove the last item
		// ASSERT: at this point segments[] has exactly zero or one "" string in it
	}
	function fillemptysegment(segments) {
		var pos;
		var maxsegments = 8; // normally 8 segments

		if (segments[segments.length-1].indexOf(".") != -1) // found a "." which means IPv4
		{	// IPv4 addresses take up two segments
			// alert ("only seven segments");
			maxsegments = 7;
		}
		for (pos=0; pos<maxsegments; pos++)	// scan to find position of the ""
		{
			if (segments[pos] == '') {
			segments[pos] = "0";	// Fill the empty segment with "0"
			break;
			}
		}

		// Now splice in enough "0000" entries in the array to flesh it out to right number
		while (segments.length < maxsegments)	// if it's not long enough
		{
			segments.splice(pos, 0, "0");	// insert one more "0" at this position
		}
	}

	// strip leading zeroes from every segment
	function stripleadingzeroes(segments) {
		var numsegs = segments.length;
		var segment;

		for (i=0; i<numsegs; i++)	// for each of the segments
		{
			segs=segments[i].split("");	// split the segment apart
			for (j=0; j<3 ; j++)	// scan through at most three characters
			{
				// alert(segs);
				if ((segs[0] == "0") && (segs.length > 1))	// if leading zero and not last character
					segs.splice(0,1);	// take it out
				else break;	// non-zero or last character - break out
			}
			segments[i] = segs.join("");	// put 'em back together
		}
	}

	// find longest sequence of zeroes and coalesce them into one segment
	// coalesce the left-most sequence if there's a tie of lengths
	function removeconsecutivezeroes(segments) {
		var bestpos = -1;	// bestpos contains position of longest sequence
		var bestcnt = 0;	// bestcnt contains the number of occurrences
		var inzeroes = false;	// assume we start in zeroes
		var curcnt = 0;
		var curpos = -1;
		var i;

		for (i=0; i<8; i++)
		{
			// alert (i.toString() + " " + inzeroes.toString() + " " + bestpos.toString() + " " + bestcnt.toString() + " ");
			if (inzeroes)	// we're in a run of zero segments
			{
				if (segments[i] == "0")	// one more - just count it
				curcnt += 1;
				else	// found the end of it
				{
					inzeroes = false;	// not in zeroes anymore
					if (curcnt > bestcnt)
					{ bestpos = curpos; bestcnt = curcnt; } // remember this place & count
				}
			}
			else	// not in a run of zeroes
			{
				if (segments[i] == "0")	// found one!
				{ inzeroes = true; curpos = i; curcnt = 1; }
			}
		}
		if (curcnt > bestcnt)
		{ bestpos = curpos; bestcnt = curcnt; } // remember this place & count

		// now take out runs of zeroes that are longer than one occurrance
		if (bestcnt > 1)
		{
			segments.splice(bestpos, bestcnt, "");
		}
	}

	// Assemble best representation of the string
	function assemblebestrepresentation(segments)
	{
	var beststr = "";
	var segslen = segments.length;
	if (segments[0] == "")
	beststr = ":";
	for (i=0; i<segslen; i++)
	{
	beststr = beststr + segments[i];
	if (i == segslen-1) break;
	beststr = beststr + ":";
	}
	if (segments[segslen-1] == "")
	beststr = beststr + ":";
	return beststr;
	}

	function isMaskIPV6CIDR(maskValue) {
		if ( (maskValue > 0) && (maskValue < 129)) {
			return true;
		} 
	}
	function isSubSubMaskIPV6CIDR(maskValue) {
		if ( (parseInt(maskValue) > parseInt(inputMask)) && (parseInt(maskValue) < 129)) {
			return true;
		} 	
	}
	//********************************** above is ipv6 code

	function convertNetmaskToWildcard(netmask) {
		var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		var netmaskArray = netmask.match(ipPattern);

		for (i = 1; i < 5; i++) {
			var hosts = 0;
			thisSegment = parseInt(netmaskArray[i]);
			wildcardMask = wildcardMask + (255 - thisSegment);
			if (i < 4) wildcardMask = wildcardMask + ".";
		}
	}

	function convertWildcardToNetmask(wildcard) {
		var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		var netmaskArray = wildcard.match(ipPattern);

		for (i = 1; i < 5; i++) {
			var hosts = 0;
			thisSegment = parseInt(netmaskArray[i]);
			finalNetmask = finalNetmask + (255 - thisSegment);
			if (i < 4) finalNetmask = finalNetmask + ".";
		}
	}

	function findMaskFromHosts(reqHosts) {
		reqHosts = reqHosts.replace(/#/,"");
		highlightHosts = "success";
		requiredHosts = ' (Requested: ' + reqHosts + ')';
		if (parseInt(reqHosts) > 65534) { return; }
		if (parseInt(reqHosts) > 32766) { return 16; }
		if (parseInt(reqHosts) > 16382) { return 17; }
		if (parseInt(reqHosts) > 8190) { return 18; }
		if (parseInt(reqHosts) > 4094) { return 19; }
		if (parseInt(reqHosts) > 2046) { return 20; }
		if (parseInt(reqHosts) > 1022) { return 21; }
		if (parseInt(reqHosts) > 510) { return 22; }
		if (parseInt(reqHosts) > 254) { return 23; }
		if (parseInt(reqHosts) > 126) { return 24; }
		if (parseInt(reqHosts) > 62) { return 25; }
		if (parseInt(reqHosts) > 30) { return 26; }
		if (parseInt(reqHosts) > 14) { return 27; }
		if (parseInt(reqHosts) > 6) { return 28; }
		if (parseInt(reqHosts) > 2) { return 29; }
		if (parseInt(reqHosts) > 1) { return 30; }
        return;

	}

	function trim(stringToTrim) {
		stringToTrim = stringToTrim.replace(/\s+/g, " ");
		return stringToTrim.replace(/^\s+|\s+$/g,"");
	}

	function determineNetworkAddress(ip,netmask) {
		var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		var netmaskArray = netmask.match(ipPattern);
		var ipArray = ip.match(ipPattern);

		for (i = 1; i < 5; i++) {
			var hosts = 0;
			thisSegment = parseInt(ipArray[i]);
			if (netmaskArray[i] == 255) {
				networkIP = networkIP + thisSegment;
				usableFirst = usableFirst + thisSegment;
				broadcastIP = broadcastIP + thisSegment;
				usableLast = usableLast + thisSegment;
			} else {
				hosts = 256 - netmaskArray[i];
				for (var j = 0; j < 256; j=j+hosts) {
					if ( (thisSegment >= j ) && (thisSegment < j+hosts)) {
						networkIP = networkIP + j;
						broadcastIP = broadcastIP + (j + hosts - 1);
						if (i == 4) {
							usableFirst = usableFirst + (j + 1);
							usableLast = usableLast + (j + hosts - 2);
						} else {
							usableFirst = usableFirst + j;
							usableLast = usableLast + (j + hosts - 1);
						}

						break;
					}
					
				}
			}
			if (i < 4) networkIP = networkIP + ".";
			if (i < 4) broadcastIP = broadcastIP + ".";
			if (i < 4) usableFirst = usableFirst + ".";
			if (i < 4) usableLast = usableLast + ".";

		}
	}

	function findIPType(IPValue){
		if (verifyIP(IPValue) == true) { 
			return "ipv4"; 
		}

		ipv6Pattern = /^((?=.*::)(?!.*::.+::)(::)?([\dA-F]{1,4}:(:|\b)|){5}|([\dA-F]{1,4}:){6})((([\dA-F]{1,4}((?!\3)::|:\b|$))|(?!\2\3)){2}|(((2[0-4]|1\d|[1-9])?\d|25[0-5])\.?\b){4})$/i;
		if (IPValue.match(ipv6Pattern)) { 
			var numOfColons = IPValue.split(/:/g).length -1;
			if (numOfColons > 7) {
				return "invalid";
			}
			return "ipv6"; 
		}

		return "invalid";
	}

	function verifyIP (IPvalue) {
		var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		var ipArray = IPvalue.match(ipPattern);
		if (ipArray == null) {
			return false;
		} else {
			for (i = 1; i < 5; i++) {
				thisSegment = ipArray[i];
				if (thisSegment > 255) {
					return false;
				}
				if ((i == 0) && (thisSegment > 255)) {
					return false;
				}
			}
		}
		return true;
	}

	function verifyMask(maskValue) {
		// check for proper cidr notation value
		if ( (maskValue > 0) && (maskValue < 33)) {
			return true;
		}

		// check if proper IP format
		var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		var ipArray = maskValue.match(ipPattern);

		if (ipArray == null) {
			return false;
		} else {
			for (i = 1; i < 5; i++) {
				thisSegment = parseInt(ipArray[i]);
				if (i > 2) {
					if (parseInt(ipArray[i-1]) < thisSegment) {
						return false;
					}
				}
				if ( (thisSegment == 255) || (thisSegment == 254) || (thisSegment == 252) || (thisSegment == 248) || (thisSegment == 240) || (thisSegment == 224) || (thisSegment == 192) || (thisSegment == 128) || (thisSegment == 0) )  {
					// do nothing
				} else {
					return false;
				}
			}
		}	

		return true;
	}
	function verifyWildcard(wcardValue) {
		// check if this is a proper wildcard mask
		wcardValue = wcardValue + ""; // converting this to a string!
		var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		var ipArray = wcardValue.match(ipPattern);

		if (ipArray == null) {
			return false;
		} else {
			for (i = 1; i < 5; i++) {
				thisSegment = parseInt(ipArray[i]);

				if ((i == 1) && (thisSegment !=0)) {
						return false;
				}
				if (i > 2) {
					if (parseInt(ipArray[i-1]) > thisSegment) {
						return false;
					}
				}
				if ( (thisSegment == 255) || (thisSegment == 127) || (thisSegment == 63) || (thisSegment == 31) || (thisSegment == 15) || (thisSegment == 7) || (thisSegment == 3) || (thisSegment == 1) || (thisSegment == 0) )  {
					// do nothing
				} else {
					return false;
				}
			}
		}	

		return true;
	}

	function isMaskCIDR(maskValue) {
		if ( (maskValue > 0) && (maskValue < 33)) {
			return true;
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
	function convertCIDRtoNetmask(maskValue) {
		if (maskValue == 0) return "0.0.0.0";
		if (maskValue == 1) return "128.0.0.0";
		if (maskValue == 2) return "192.0.0.0";
		if (maskValue == 3) return "224.0.0.0";
		if (maskValue == 4) return "240.0.0.0";
		if (maskValue == 5) return "248.0.0.0";
		if (maskValue == 6) return "252.0.0.0";
		if (maskValue == 7) return "254.0.0.0";
		if (maskValue == 8) return "255.0.0.0";

		if (maskValue == 9 ) return "255.128.0.0";
		if (maskValue == 10) return "255.192.0.0";
		if (maskValue == 11) return "255.224.0.0";
		if (maskValue == 12) return "255.240.0.0";
		if (maskValue == 13) return "255.248.0.0";
		if (maskValue == 14) return "255.252.0.0";
		if (maskValue == 15) return "255.254.0.0";
		if (maskValue == 16) return "255.255.0.0";

		if (maskValue == 17) return "255.255.128.0";
		if (maskValue == 18) return "255.255.192.0";
		if (maskValue == 19) return "255.255.224.0";
		if (maskValue == 20) return "255.255.240.0";
		if (maskValue == 21) return "255.255.248.0";
		if (maskValue == 22) return "255.255.252.0";
		if (maskValue == 23) return "255.255.254.0";
		if (maskValue == 24) return "255.255.255.0";

		if (maskValue == 25) return "255.255.255.128";
		if (maskValue == 26) return "255.255.255.192";
		if (maskValue == 27) return "255.255.255.224";
		if (maskValue == 28) return "255.255.255.240";
		if (maskValue == 29) return "255.255.255.248";
		if (maskValue == 30) return "255.255.255.252";
		if (maskValue == 31) return "255.255.255.254";
		if (maskValue == 32) return "255.255.255.255";
	}

	function determineClass(ipValue) {
		var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		var ipArray = ipValue.match(ipPattern);

		firstSegment = ipArray[1];
		if ( (firstSegment >= 0) && (firstSegment < 128) ) {
				return "A (0.0.0.0 - 127.255.255.255)";
		}
		if ( (firstSegment >= 128) && (firstSegment < 192) ) {
				return "B (128.0.0.0 - 191.255.255.255)";
		}
		if ( (firstSegment >= 192) && (firstSegment < 224) ) {
				return "C (192.0.0.0 - 223.255.255.255)";
		}
		if ( (firstSegment >= 224) && (firstSegment < 240) ) {
				return "D (224.0.0.0 - 239.255.255.255)";
		}
		if ( (firstSegment >= 240) && (firstSegment < 256) ) {
				return "E (240.0.0.0 - 255.255.255.255)";
		}



	}

	// function adds commas to thousands places
	function addCommas(nStr){
		nStr += '';
		x = nStr.split('.');
		x1 = x[0];
		x2 = x.length > 1 ? '.' + x[1] : '';
		var rgx = /(\d+)(\d{3})/;
		while (rgx.test(x1)) {
			x1 = x1.replace(rgx, '$1' + ',' + '$2');
		}
		return x1 + x2;
	}

	// function determines what the previous network is and calculates it out
	$(document).on('click','.netprev', function(){
		var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		var ipArray = networkIP.match(ipPattern);
		var seg1 = parseInt(ipArray[1]);
		var seg2 = parseInt(ipArray[2]);
		var seg3 = parseInt(ipArray[3]);
		var seg4 = parseInt(ipArray[4]);
		if (seg4 == "0") {
			if (seg3 == "0") {
				if (seg2 == "0") {
					if (seg1 != "0") {
						seg4 = 255;
						seg3 = 255;
						seg2 = 255;
						seg1 = seg1 - 1;				
					}
				} else {
					seg4 = 255;
					seg3 = 255;
					seg2 = seg2 - 1;
				}
			} else {
				seg4 = 255;
				seg3 = seg3 - 1;
			}
		} else {
			 seg4 = seg4 - 1;
		}
		document.subnet.ip.value = seg1 + '.' + seg2 + '.' + seg3 + '.' + seg4 + ' ' + finalNetmask; 
		_gaq.push(['_trackEvent', 'Subnet Calculator', 'Network Backward', 'Clicked',, false]);
		$("#calculate").click();
	});

	// function determines what the previous network is and calculates it out
	$(document).on('click','.netnext', function(){
		var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
		var ipArray = broadcastIP.match(ipPattern);
		var seg1 = parseInt(ipArray[1]);
		var seg2 = parseInt(ipArray[2]);
		var seg3 = parseInt(ipArray[3]);
		var seg4 = parseInt(ipArray[4]);
		if (seg4 == "255") {
			if (seg3 == "255") {
				if (seg2 == "255") {
					if (seg1 != "255") {
						seg4 = 0;
						seg3 = 0;
						seg2 = 0;
						seg1 = seg1 + 1;				
					}
				} else {
					seg4 = 0;
					seg3 = 0;
					seg2 = seg2 + 1;
				}
			} else {
				seg4 = 0;
				seg3 = seg3 + 1;
			}
		} else {
			 seg4 = seg4 + 1;
		}
		document.subnet.ip.value = seg1 + '.' + seg2 + '.' + seg3 + '.' + seg4 + ' ' + finalNetmask;  
		_gaq.push(['_trackEvent', 'Subnet Calculator', 'Network Forward', 'Clicked',, false]);
		$("#calculate").click();
	});

	// User clicks the Random Button
 	$("#random").click(function(){
 		// varA - rand(1 - 223)
 		var segA = Math.floor(Math.random()*223) + 1;
 		// mask = dependant on class. 0-127 = A, 128-191 = B, 192-223 = C
 		if (segA < 128) {
 			randCIDR = Math.floor(Math.random()*22) + 8;
 		} else if (segA < 192) {
 			randCIDR = Math.floor(Math.random()*14) + 16;
 		} else {
 			randCIDR = Math.floor(Math.random()*7) + 24;
 		}
 		var segB = Math.floor(Math.random()*256);
 		var segC = Math.floor(Math.random()*256);
 		var segD = Math.floor(Math.random()*256);
 		var cointoss = Math.floor(Math.random()*2);
 		if (cointoss == 0) {  // half the time do cidr, half the time do netmask
	 		randNetmask = " " + convertCIDRtoNetmask(randCIDR);
 		} else {
 			randNetmask = "/" + randCIDR;
 		}

 		_gaq.push(['_trackEvent', 'Subnet Calculator', 'Random IP', 'Clicked',, false]);

 		randomIP = segA + "." + segB + "." + segC + "." + segD + randNetmask;
		document.subnet.ip.value = randomIP;

		clearResults();
 	});

 	function clearResults() {
 		var output = '<table class="table table-striped table-hover">' +
			'<tr><td><strong>IP Address:</strong></td><td></td></tr>' +
			'<tr><td><strong>Netmask:</strong></td><td></td></tr>' +
			'<tr><td><strong>Wildcard Mask:</strong></td><td></td></tr>' +
			'<tr><td><strong>CIDR Notation:</strong></td><td></td></tr>' +
			'<tr><td><strong>Network Address:</strong></td><td></td></tr>' +
			'<tr><td><strong>Usable Host Range:</strong></td><td></td></tr>' +
			'<tr><td><strong>Broadcast Address:</strong></td><td></td></tr>' +
			'<tr><td><strong>Binary Netmask:</strong></td><td></td></tr>' +
			'<tr><td><strong>Total number of hosts:</strong></td><td></td></tr>' +
			'<tr><td><strong>Number of usable hosts:</strong></td><td></td></tr>' +
			'<tr><td><strong>IP Class:</strong></td><td></td></tr>' +
			'</table>';			
        $("#results").html(output);
 	}

	// Restrict enter key from submitting form. Instead make it click the calculate button.
	document.getElementById('form').onsubmit = function () {
    	$("#calculate").click();
    	return false;
	}

	// Function will get any GET variables in the URL
	function getUrlVars() {
	  var vars = {};
      var parts = window.location.href.replace(/[?&]+([^=&]+)=([^&]*)/gi, function(m,key,value) {
          vars[key] = value;
      });
      return vars;
	}
 });