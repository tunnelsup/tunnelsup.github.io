

        $(document).ready(function() {

          $("#cleanit").click(function(){
            $("#outputdata").html("");
            $("#results").css('display','block');

            var showrun = document.convert.showrun.value;
                // remove double spaces
            showrun = showrun.replace("  ", " ");
                // remove trailing and leading spaces (basically doing a trim)
            showrun = showrun.replace(/(^\s*)|(\s*$)/gi,"");
            showrun = showrun.replace(/[ ]{2,}/gi," ");
            showrun = showrun.replace(/\n /,"\n");


            var output = [];
            var eachLine = showrun.split('\n');

                var eOBJG = [];
                var eOBJ = [];
                var eACL = [];

                /*
                //var sumnum = ['January', 'February', 'March'];
                var sumnum = "January, February, March";
                var retest = /uary/;
                var resl = sumnum.match(/uary/g);
                console.log(resl);
                console.log(resl.length);
                */
            
            // iterate over each line entered to pick out certain elements
            for (var i=0; i < eachLine.length; i++) {
                        var eachWord = eachLine[i].split(" ");

                        // look for object-group names
                        if (eachWord[0] == "object-group") {
                                eOBJG.push(eachWord[1]);
                                eOBJG.push(eachWord[2]);
                        }
                        // look for objects names
                        if (eachWord[0] == "object") {
                                eOBJ.push(eachWord[1]);
                                eOBJ.push(eachWord[2]);
                        }

                        // get all ACL names
                        if (eachWord[0] == "access-list") {
                                var found = 0;
                                for (var j=0; j < eACL.length; j++) {
                                        if (eachWord[1] == eACL[j]) {
                                                found = 1;
                                        }
                                }
                                if (found == 0) {
                                        eACL.push(eachWord[1]);
                                }
                        }


            }

                // Find all unused object groups
                for (var i=1; i < eOBJG.length; i=i + 2) {
                        var REsearch = new RegExp(eOBJG[i],'g');
                        var REresult = showrun.match(REsearch);
                        if (REresult.length == 1) {
                                output.push("<em>! Unused object-group found; suggest removing it</em>");
                                output.push("no object-group " + eOBJG[i-1] + " " + eOBJG[i]);
                        }
                }

                // Find all unused objects
                for (var i=1; i < eOBJ.length; i=i + 2) {
                        var REsearch = new RegExp(eOBJ[i],'g');
                        var REresult = showrun.match(REsearch);
                        if (REresult.length == 1) {
                                output.push("<em>! Unused object found; suggest removing it</em>");
                                output.push("no object " + eOBJ[i-1] + " " + eOBJ[i]);
                        }
                }

                // Find all unused acl's
                for (var i=0; i < eACL.length; i=i + 1) {
                        // find all occurances of ^access-list ACLNAME
                        var REacl = "^access-list " + eACL[i] ;
                        var REaclre = new RegExp(REacl,'gm');
                        var REaclsearch = showrun.match(REaclre);
                        console.log(REaclsearch.length);

                        // find all occurances of ACLNAME
                        var REsearch = new RegExp(eACL[i],'g');
                        var REresult = showrun.match(REsearch);

                        var timesFound = REresult.length - REaclsearch.length;
                        if (timesFound == 0) {
                                output.push("<em>! Unused ACL found; suggest removing it</em>");
                                output.push("clear config access-list " + eACL[i]);
                        }

                }



                /*
            for (var i=0; i < eachLine.length; i++) {
                        output.push(eachLine[i]);
            }
                */
            if (output.length == 0) {
                    output.push("! No items found to cleanup.");
            }
            output.push("! Analyzed "+eachLine.length+" lines of code." );

            // Places the output to the page
            for (var i=0; i < output.length; i++) {
                        $("#outputdata").append(output[i]);
                        $("#outputdata").append('<br />');
            }
 
            // Scroll down to results
            $('html, body').animate({
                        scrollTop: $("#results").offset().top
            }, 1000);
 
          });
        });
