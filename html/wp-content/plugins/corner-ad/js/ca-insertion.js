jQuery(function(){
	(function($){
        window ['open_insertion_corner_ad_window'] = function(){
			
        	var cont = '<div title="Insert Corner Ad" style="text-align:center;"><div style="padding-top:20px;"><div style="clear:both;">Select the AD to insert</div><div><select id="corner_ad" style="width:250px;display:block !important;visibility:visible !important;">'+corner_ad.list+'</select></div></div></div>';
	
			$(cont).dialog({
				dialogClass: 'wp-dialog',
				modal: true,
				closeOnEscape: true,
                close: function(){
                    $(this).remove();
                },
				buttons: [
					{text: 'OK', click: function() {
						var ca  = '[corner-ad id='+$('#corner_ad').val()+']';
						if(send_to_editor) send_to_editor(ca);
						$(this).dialog("close"); 
					}}
				]
			});
		};    
	})(jQuery)
})