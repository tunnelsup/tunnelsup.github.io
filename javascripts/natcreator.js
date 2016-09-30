 $(document).ready(function() {
  $("#convertit").click(function(){
    document.convert.nat84.value = "";

    var input = document.convert.nat82.value;
        // remove double spaces
    input = input.replace("  ", " ");
        // remove trailing and leading spaces (basically doing a trim)
    input = input.replace(/(^\s*)|(\s*$)/gi,"");
    input = input.replace(/[ ]{2,}/gi," ");
    input = input.replace(/\n /,"\n");
    var invalid = 0;

    var output = [];
    var eachLine = input.split('\n');
    
    // iterate over each line entered
    for (var i=0; i < eachLine.length; i++) {
        var line1 = eachLine[i];
        if (line1 == "") {
                continue;
        }
        var token = line1.split(' ');

        //conduct form validation
        if (token.length != 4) {
                output.push("! NAT'ing: " + line1);
                output.push("! Error: Didn't find all 4 fields");
                invalid++;
                continue;
        }
        var ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        var ipArray = token[2].match(ipPattern);
        if (ipArray == null) {
                invalid++;
        }
        ipArray = token[3].match(ipPattern);
        if (ipArray == null) {
                invalid++;
        }


        var obj1 = "OBJ-" + token[2];
        var obj2 = "OBJ-" + token[3];
          
        output.push("! NAT'ing: " + line1);
        _gaq.push(['_trackEvent', 'NAT Creator', 'Create', 'Clicked',, false]);

        if (invalid > 0) {
                output.push("! Error: you aren't doing it right");

        } else {
                //prepare output
                output.push("object network " + obj1);
                output.push(" host " + token[2]);
                output.push("object network " + obj2);
                output.push(" host " + token[3]);
                output.push("nat (" + token[0] + "," + token[1] + ") source static " + obj1 + " " + obj2);
                output.push("");

        }
    }
 

    // Places the output into the textarea
    for (var i=0; i < output.length; i++) {
        document.convert.nat84.value = document.convert.nat84.value + "\n" + output[i];
    }

  });
 });
