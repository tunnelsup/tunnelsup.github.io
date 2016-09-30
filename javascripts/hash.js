/*************************************************** 
    Hash Analyzer tool created by TunnelsUp.com
 **************************************************/

// Declare a few globals


 $(document).ready(function() {
	$("#analyze").click(function(){
       	// reset vars
       	$(".errorMessage").html("");
       	$(".results").html("");

       	var hashtype = 'unknown';
	    var input = trim(document.analyzer.hash.value);
	    var charlength = input.length;
	    // CLASSIFY INPUTS
	    var bitlength = 0;
	    if (ishex(input)) {
	    	var chartype = 'hexidecimal';
	    	bitlength = input.length * 4;
	    }




	    // ANALYZE CLASSIFIED INPUTS
	    if ((chartype == 'hexidecimal') && (bitlength == 128)) {
 			hashtype = 'MD5';
		}
	    if ((chartype == 'hexidecimal') && (bitlength == 160)) {
 			hashtype = 'SHA1 (or SHA 128)';
		}	   
		if ((chartype == 'hexidecimal') && (bitlength == 256)) {
 			hashtype = 'SHA2-256';
		}
		if ((chartype == 'hexidecimal') && (bitlength == 384)) {
 			hashtype = 'SHA2-384';
		}
		if ((chartype == 'hexidecimal') && (bitlength == 512)) {
 			hashtype = 'SHA2-512';
		}
		if ((chartype == 'hexidecimal') && (bitlength == 64)) {
 			hashtype = 'MySQL < version 4.1';
		}
		if (charlength == 41) {
			if (input[0] == "*") {
				if (ishex(input.substring(1))) {   // check if the string after the * is hex
					hashtype = 'MySQL5';
					chartype = 'star followed by hexidecimal';
					bitlength = 4 * 40;
				}
			}
		}
		if (charlength == 34) {
			if ((input[0] == '$') && (input[1] == 'P') && (input[2] == '$')) {
				if (isalphanumeric(input[3])) {
					hashtype = 'MD5 Wordpress';
					chartype = '$P$ followed by alphanumerics';
					bitlength = 6 * 31;
				}
			}
		}
		if (charlength == 34) {
			if ((input[0] == '$') && (input[1] == 'H') && (input[2] == '$')) {
				if (isalphanumeric(input[3])) {
					hashtype = 'MD5 phpBB3';
					chartype = '$H$ followed by alphanumerics';
					bitlength = 6 * 31;
				}
			}
		}


/*
chee@beebin:~$ sudo doveadm pw -s MD5    (MD5-Crypt(3) Requires a salt! example below uses 8 byte salt)
{MD5}$1$8ade6fc1$0MJXOZOOpbQovXtQEyrUP1

chee@beebin:~$ sudo doveadm pw 
{CRAM-MD5}9186d855e11eba527a7a52ca82b313e180d62234f0acc9051b527243d41e2740

chee@beebin:~$ sudo doveadm pw -s HMAC-MD5
{HMAC-MD5}9186d855e11eba527a7a52ca82b313e180d62234f0acc9051b527243d41e2740

chee@beebin:~$ sudo doveadm pw -s PLAIN-MD5
{PLAIN-MD5}5f4dcc3b5aa765d61d8327deb882cf99
*/


	    // CREATE OUTPUT
		var output = '<table class="table table-striped table-hover">'+
			'<tr><td><strong>Hash type:</strong></td><td>'+hashtype+'</td></tr>'+
			'<tr><td><strong>Bit length:</strong></td><td>'+bitlength+'</td></tr>	'+			
			'<tr><td><strong>Character length:</strong></td><td>'+charlength+'</td></tr>	'+			
			'<tr><td><strong>Character type:</strong></td><td>'+chartype+'</td></tr>'+		
		'</table>';
		$('#results').html(output);
	});


	function ishex(num){ 
		var validChar='0123456789ABCDEFabcdef'; 
		var flag=true; 
		var x=num.toUpperCase(); 
		for(idx=0;idx<x.length;idx++){ 
			if(validChar.indexOf(x.charAt(idx))<0){ 
				return false; 
			} 
		} 
		return true; 
	} 
	function isalphanumeric(num){ 
		var validChar='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'; 
		var flag=true; 
		var x=num.toUpperCase(); 
		for(idx=0;idx<x.length;idx++){ 
			if(validChar.indexOf(x.charAt(idx))<0){ 
				return false; 
			} 
		} 
		return true; 
	} 
	function trim(stringToTrim) {
		stringToTrim = stringToTrim.replace(/\s+/g, " ");
		return stringToTrim.replace(/^\s+|\s+$/g,"");
	}
 });