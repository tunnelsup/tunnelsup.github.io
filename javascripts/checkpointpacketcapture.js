$(document).ready(function() {
    $("#create").click(function(){
	    var srcip = trim(document.creator.srcip.value);
	    var dstip = trim(document.creator.dstip.value);
	    var dstport = trim(document.creator.dstport.value);
	    var file = trim(document.creator.file.value);
	    var config;
	    $(".errorMessage").html("");

    	if (!verifyIP(srcip)) { 
 	    	$(".errorMessage").html("Invalid source IP address.");
 	    	return;
	    }
	    if (!verifyIP(dstip)) { 
 	    	$(".errorMessage").html("Invalid destination IP address.");
 	    	return;
	    }
	    if (!verifyPort(dstport)) { 
 	    	$(".errorMessage").html("Invalid destination port.");
 	    	return;
	    }
	    if (!verifyFile(file)) { 
 	    	$(".errorMessage").html("Invalid filename. Only letters, numbers, period and dashes allowed.");
 	    	return;
	    }

	    if ( (srcip == "any") && (dstip == "any") && (dstport == "any") ) {
	    	result = "fw monitor";
	    	if (file != "") {
	    		result = result + " -o " + file;
	    	}
	    } else {
	    	result = 'fw monitor -e \'accept ';

	    	// create the config for the port if need be
	    	if (dstport != "any") {
	    		result = result + "([20:2,b]=" + dstport + " or [22:2,b]=" + dstport + ")";
	    	}

	    	// find out if we need comma between ports and IPs in result
	    	if ( (dstport != "any") && (srcip != "any") ) {
	    		result = result + ", ";
	    	} else if ( (dstport != "any") && (dstip != "any") ) {
	    		result = result + ", ";
	    	} else {
	    		result = result + " ";
	    	}

	    	if ( (srcip != "any") && (dstip != "any") ) {
	    		result = result + '(([12:4,b]='+srcip+' ,[16:4,b]='+dstip+') or ([12:4,b]='+dstip+' ,[16:4,b]='+srcip+'))';
	    	} else if ( (srcip != "any") && (dstip == "any") ) {
	    		result = result + '([12:4,b]='+srcip+')';
	    	} else if ( (srcip == "any") && (dstip != "any") ) {
				result = result + '([16:4,b]='+dstip+')';
	    	}

	    	// end the expression -e portion of the config
    		result = result + ";'";

	    	if (file != "") {
	    		result = result + " -o " + file;
	    	}


	    }

//	    fw monitor -e 'accept ([20:2,b]=5668 or [22:2,b]=5668), (([12:4,b]=161.220.180.35 ,[16:4,b]=209.114.165.202) or ([12:4,b]=209.114.165.202 ,[16:4,b]=161.220.180.35));'

		$("#results").html(result);

    });

	function verifyFile(inputtxt) {  
	  if (inputtxt == "") {
	  	return true;
	  } 
      var letters = /^[A-Za-z0-9\.\-]+$/;  
      if(inputtxt.match(letters)) {  
      	return true;  
      } else {  
	    return false;  
      }  
    }  


	function verifyIP (IPvalue) {
		if (IPvalue == "any") {
			return true;
		}
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

	function verifyPort (port) {
		if (port == "any") {
			return true;
		}
		if ( (port >= 0) && (port <= 65535) ) {
			return true;
		}
	}	

    function trim(stringToTrim) {
        stringToTrim = stringToTrim.replace(/\s+/g, " ");
        stringToTrim = stringToTrim.replace(/[ ]{2,}/gi," ");
        stringToTrim = stringToTrim.replace(/\n /,"\n");
        return stringToTrim.replace(/^\s+|\s+$/g,"");
    }
});