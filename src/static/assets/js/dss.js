$("#settings").submit(function(e) {
    e.preventDefault(); // prevent actual form submit
    var form = $(this);
    var url = form.attr('action'); 
    $.ajax({
         type: "POST",
         url: url,
         data: form.serialize(), // serializes form input
         success: function(data){
             console.log(data);
             alert("Settings Saved");
         }
    });
});

function toggle_config(e) {
    var settings = document.getElementById('config');

    if (settings.style.display == 'block') {
        settings.style.display = 'none';
        e.innerHTML = 'Show Configuration';
    }
    else {
        settings.style.display = 'block';
        e.innerHTML = "Hide Configuration";
    }
}

function refresh_scan_status(url) {
    $.ajax({
        type: "GET",
        url: url,
		dataType: 'json',
        success: function(data){
            console.log(data);
			json = JSON.parse(data);
			$('#scan_num').html(json.scan.scan_num);
			$('#scan_type').html(json.scan.scan_type);
			$('#started').html(json.scan.started);
			$('#completed').html(json.scan.completed);
			$('#elapsed').html(json.scan.elapsed);
			$('#status').html(json.scan.status);

			$('#thread_info').empty();
			$('#thread_info').append(("<ul id='thread_list'></ul>"));

			for (var i = 0; i < json['threads'].length; i++){
				thread  = json['threads'][i];
				$("#thread_list").append("<li>" + thread.scan_thread_num  + ":" + thread.status + "</li>");
			}
		
			var pending = [];
			var scanned = [];
			var skipped = [];
			var scanning = [];
			
			for (var i = 0; i < json['scan_results'].length; i++){
				scan_result = json['scan_results'][i];
				if (scan_result.status == 'Pending'){
					pending.push(scan_result);
				} else if (scan_result.status == 'Finished'){
					scanned.push(scan_result);
				} else if (scan_result.status == 'Skipped'){
					skipped.push(scan_result);	
				} else if (scan_result.status == 'Scanning'){
					scanning.push(scan_result);	
				}
			}
			update_statuses('pending', pending);
			update_statuses('scanned', scanned);
			update_statuses('skipped', skipped);
			update_statuses('scanning', scanning);
			if (json.scan.status == 'Finished'){
				$('#report').show();
			}
         }
    });
}

function update_statuses(target, scan_results){
	values = "<ul>";
	for (var i = 0; i < scan_results.length; i++){
		scan_result = scan_results[i];
		values += "<li>" + scan_result.repo_location + "</li>";
	}
	values += "</ul>"
	$('#' + target).html(values);
	$('#' + target + '_count').html('(' + scan_results.length +')');
}

// Message Method
function disp_message(x){
    $('#scan_err').show();
    $("#err_msg").text(x);
    // $('#jerror').show();
}

// Error message
$('#scan_form').submit(function(event) {
    if($('#github').is(':checked')) { 
        var org = $.trim($("#otext").val());
        var user = $.trim($("#utext").val());
        if(org == "" && user == ""){
            event.preventDefault();
            disp_message(" Must indicate Github Orgs and/or Github Users");
            return;
        }
    } else if($('#bitbucket').is(':checked')){
        var bg = $.trim($("#BGurl").val());
        if(bg == ""){
            event.preventDefault();
            disp_message(" Must indicate Bitbucket URL");
            return;
        }
    } else if($('#gitlab').is(':checked')){
        var bg = $.trim($("#BGurl").val());
        if(bg == ""){
            event.preventDefault();
            disp_message(" Must indicate Gitlab URL");
            return;
        }
    } else if($('#azure').is(':checked')){
        var azure_organization = $.trim($("#azure_organization").val());
        if(azure_organization == ""){
            event.preventDefault();
            disp_message("Please supply an Azure Organization");
            return;
        }
    } else if($('#generic').is(':checked')){
        var git = $.trim($("#gtext").val());
        if(git == ""){
            event.preventDefault();
            disp_message(" Must indicate Git URLs");
            return;
        }
    }
    $("#scanning_msg").show();
});

// This function changes the source   
$(document).ready(function() {
    $("input[name$='gitgroup']").click(function(){
        var repo_type = $(this).val();
        $('.gitscan_form').hide();
		$('.gitscan_form.' + repo_type).show();
    });
});
