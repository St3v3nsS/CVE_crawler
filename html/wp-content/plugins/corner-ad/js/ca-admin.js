jQuery(function(){
	(function($){
        // Main application
		jQuery('.corner_ad_button_for_upload').click(function(){
			var corner_ad_img_path_field = jQuery(this).prev('input[type="text"]');
			var media = wp.media({
					title: 'Select Media File',
					library:{
						type: 'image'
					},
					button: {
					text: 'Select Item'
					},
					multiple: false
			}).on('select', 
				(function( field ){
					return function() {
						var attachment = media.state().get('selection').first().toJSON();
						var url = attachment.url;
						field.val( url );
					};
				})( corner_ad_img_path_field )	
			).open();
			return false;
		});
		
        jQuery('.corner_ad_thumb_chk').click(function(){
			var e 		 = jQuery( this ),
				thumbBtn = e.prev( 'input' ),
				thumbBox = thumbBtn.prev( 'input' ),
				action 	 = 'show';
				
			if( e.is(':checked') )
			{
				action = 'hide';
				thumbBox.val('');
			}	
				
			
			thumbBox[ action ]();
			thumbBtn[ action ]();
		});
		
        jQuery('.corner_ad_button_for_add_img_field').click(function(){
            alert('Only one image may be associated to the Ad in the free version of plugin');
			return false;
		});
    })(jQuery)
})