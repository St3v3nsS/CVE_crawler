<?php

/* FUNCTIONS RELATED TO THE SETTINGS PAGE OF CORNER AD */ 

if(!function_exists('corner_ad_settings_page_list')){
    function corner_ad_settings_page_list(){
        global $wpdb;
        $ad = $wpdb->get_row("SELECT * FROM ".$wpdb->prefix.CORNER_AD_TABLE);
        
        $output = '<div class="postbox">
                        <h3 class="handle" style="padding:5px;"><span>'.__('Select a Corner Ad or create a new one', CORNER_AD_TD).'</span></h3>
                            <div class="inside"><p  style="border:1px solid #E6DB55;margin-bottom:10px;padding:5px;background-color: #FFFFE0;">'.__('If you want test the premium version of Corner Ad go to the following links:<br/> <a href="http://demos.net-factor.com/corner-ad/wp-login.php" target="_blank">Administration area: Click to access the administration area demo</a><br/> <a href="http://demos.net-factor.com/corner-ad/" target="_blank">Public page: Click to access the Corner Ad</a>').'
					</p>';
        
        if($ad){
            $create_btn = '<div><input type="button" class="button-primary" onclick="alert(\'Only one Ad may be created in the free version of plugin\')" value="'.esc_attr(__('Create New Ad', CORNER_AD_TD)).'" /></div>';
            
            $output .= $create_btn;
            $output .= '<table class="form-table">
                <thead>
                <th style="white-space:nowrap;font-weight:bold;">Ad name</th><th style="font-weight:bold;">Actions</th><th style="font-weight:bold;">Shortcode</th><th style="white-space:nowrap;width:100%;font-weight:bold;">The Ad has been selected</th>
                </thead>
            ';
                        
            $output .= '<tr><td style="white-space:nowrap;">'.$ad->name.'</td><td style="white-space:nowrap;"><a href="?page=corner-ad.php&action=ad_edit&id='.esc_attr($ad->id).'" class="button">'.__('Edit', CORNER_AD_TD).'</a> <a href="?page=corner-ad.php&action=ad_remove&id='.esc_attr($ad->id).'" class="button">'.__('Remove', CORNER_AD_TD).'</a> </td><td  style="white-space:nowrap;">[corner-ad id='.esc_attr($ad->id).']</td><td>Only available in the <a href="http://wordpress.dwbooster.com/content-tools/corner-ad" target="_blank">commercial</a> version of plugin</td></tr>';
            
            $output .= '</table>';
        }else{
            $create_btn = '<div><a href="?page=corner-ad.php&action=ad_create" class="button-primary">'.__('Create New Ad', CORNER_AD_TD).'</a></div>';
        }
        
        $output .= $create_btn;
        $output .='</div></div>';
        return $output;
    } // End corner_ad_settings_page_list
}

if(!function_exists('corner_ad_settings_page_form')){
    function corner_ad_settings_page_form(){
        global $wpdb; 
        
        $data;
        $error = array();
        $id;
        $output = '';
        $title = __('Create or edit a Corner Ad', CORNER_AD_TD);
        
        // Load the picker color resources
		wp_enqueue_style( 'farbtastic' );
		wp_enqueue_script( 'farbtastic' );
		wp_enqueue_style( 'thickbox' );
		wp_enqueue_script( 'thickbox' );
		wp_enqueue_script( 'corner_ad_admin_script',  CORNER_AD_PLUGIN_URL.'/js/ca-admin.js', array('jquery'));
        	
		
        
        if(isset($_REQUEST['id'])){
            $data = $wpdb->get_row($wpdb->prepare("SELECT * FROM ".$wpdb->prefix.CORNER_AD_TABLE." WHERE id=%d", $_REQUEST['id']));
            if($data){
                $id = $_REQUEST['id'];
                $corner_ad_name = $data->name;
                $corner_ad_alignTo = $data->alignTo;
                $corner_ad_mirror = $data->mirror;
                $corner_ad_colorIn = $data->colorIn;
                $corner_ad_openIn = $data->openIn;
                $corner_ad_closeIn = $data->closeIn;
                $corner_ad_adURL = $data->adURL;
                $corner_ad_target = $data->target;
                
                $corner_ad_imgPath = array();
                
                $result = $wpdb->get_row($wpdb->prepare("SELECT imgPath, thumbPath FROM ".$wpdb->prefix.CORNER_AD_IMG_TABLE." WHERE ad=%d", $id));
                if($result){
                    $corner_ad_imgPath = $result->imgPath;
                    $corner_ad_thumbPath = !empty( $result->thumbPath ) ? $result->thumbPath : '';
                }
                
                
            }
        }
        
        if(isset($_POST['corner_ad_edition_nonce']) && wp_verify_nonce($_POST['corner_ad_edition_nonce'], __FILE__)){
                if(!empty($_POST['corner_ad_name']))
                    $corner_ad_name = $_POST['corner_ad_name'];
                else
                    $error[] = __('The Ad name is required', CORNER_AD_TD);
                    
                $corner_ad_alignTo = (isset($_POST['corner_ad_alignTo']) && $_POST['corner_ad_alignTo'] == 'tr') ? 'tr' : 'tl';
                $corner_ad_mirror  = (isset($_POST['corner_ad_mirror']))  ? 1 : 0;
                $corner_ad_colorIn = (isset($_POST['corner_ad_colorIn'])) ? $_POST['corner_ad_colorIn']  : 'FFFFFF' ;
                $corner_ad_openIn  = (isset($_POST['corner_ad_openIn']))  ? $_POST['corner_ad_openIn']   : 0;
                $corner_ad_closeIn = (isset($_POST['corner_ad_closeIn'])) ? $_POST['corner_ad_closeIn']  : 0;
                if(!empty($_POST['corner_ad_imgPath'])){
                    $corner_ad_imgPath 	 = trim($_POST['corner_ad_imgPath']);
                    $corner_ad_thumbPath = ( !empty($_POST['corner_ad_thumbPath']) ) ? trim($_POST['corner_ad_thumbPath']) : $corner_ad_imgPath;
                    
					if( !empty( $corner_ad_imgPath ) )
					{	
						$img = corner_ad_get_images( $corner_ad_imgPath, $corner_ad_thumbPath );
						
						// Large
						if( !empty( $img->large->id ) )
						{
							$img_obj = wp_get_image_editor( $img->large->url );
							if( !is_wp_error( $img_obj ) ){
							
								$imgSize   = $img_obj->get_size();
								$size = min($imgSize['height'], $imgSize['width'], 500);
								add_image_size( 'corner_ad', $size, $size, true );    
							}
							$img->large->file = get_attached_file($img->large->id);
							wp_update_attachment_metadata( $img->large->id, wp_generate_attachment_metadata( $img->large->id, $img->large->file ) );
						}
							
						// Thumb
						if( !empty( $img->thumb->id ) )
						{
							$img_obj = wp_get_image_editor( $img->thumb->url );
							if( !is_wp_error( $img_obj ) ){
							
								$imgSize   = $img_obj->get_size();
								$size = min($imgSize['height'], $imgSize['width'], 100);
								add_image_size( 'corner_ad_thumb', $size, $size, true );    
							}
							$img->thumb->file = get_attached_file($img->thumb->id);
							wp_update_attachment_metadata( $img->thumb->id, wp_generate_attachment_metadata( $img->thumb->id, $img->thumb->file ) );
						}
					}
                }else{
                    $error[] = __('The Ad image is required', CORNER_AD_TD);
                }    
                
                if(!empty($_POST['corner_ad_adURL']))
                    $corner_ad_adURL = $_POST['corner_ad_adURL'];
                else
                    $error[] = __('The Ad link is required', CORNER_AD_TD);
                $corner_ad_target = (isset($_POST['corner_ad_target']) && $_POST['corner_ad_target'] == '_blank') ? '_blank' : '_self';
                
                if(count($error) == 0){
                    if(!empty($data)){ 
                        // Update
                        $success = $wpdb->update(
                            $wpdb->prefix.CORNER_AD_TABLE,
                            array(
                                'name'    => $corner_ad_name,
                                'alignTo' => 'tl',
                                'mirror'  => $corner_ad_mirror,
                                'colorIn' => $corner_ad_colorIn,
                                'openIn'  => $corner_ad_openIn,
                                'closeIn' => $corner_ad_closeIn,
                                'adURL'   => $corner_ad_adURL,
                                'target'  => $corner_ad_target
                            ),
                            
                            array(
                                'id'      => $id
                            ),
                            
                            array('%s', '%s', '%d', '%s', '%d', '%d', '%s', '%s'),
                            
                            array('%d')
                        );
                        // Remove associate images
                        $wpdb->query($wpdb->prepare("DELETE FROM ".$wpdb->prefix.CORNER_AD_IMG_TABLE." WHERE ad=%d", $id));
                        
                        if(!empty($corner_ad_imgPath))
                            $wpdb->insert(
                                $wpdb->prefix.CORNER_AD_IMG_TABLE,
                                array(
                                    'ad'      => $id,
                                    'imgPath' => $corner_ad_imgPath,
                                    'thumbPath' => $corner_ad_thumbPath
                                ),
                                array( '%d', '%s', '%s' )
                            );
                        
                    }elseif($wpdb->get_var("SELECT COUNT(id) FROM ".$wpdb->prefix.CORNER_AD_TABLE) == 0){
                        
                        // Insert
                        $success = $wpdb->insert(
                            $wpdb->prefix.CORNER_AD_TABLE,
                            array(
                                'name'    => $corner_ad_name,
                                'alignTo' => 'tl',
                                'mirror'  => $corner_ad_mirror,
                                'colorIn' => $corner_ad_colorIn,
                                'openIn'  => $corner_ad_openIn,
                                'closeIn' => $corner_ad_closeIn,
                                'adURL'   => $corner_ad_adURL,
                                'target'  => $corner_ad_target
                            ),
                            
                            array('%s', '%s', '%d', '%s', '%d', '%d', '%s', '%s')
                        );
                        
                        $id = $wpdb->insert_id;
                        
                        if(!empty($corner_ad_imgPath))
                            $wpdb->insert(
                                $wpdb->prefix.CORNER_AD_IMG_TABLE,
                                array(
                                    'ad'      => $id,
                                    'imgPath' => $corner_ad_imgPath,
                                    'thumbPath' => $corner_ad_thumbPath
                                ),
                                array( '%d', '%s', '%s' )
                            );
                    }
                    
                    $output .= '<div class="updated settings-error">'.__('The corner Ad has been stored successfully', CORNER_AD_TD).'</div>';
                }    
        }
        
        
        $title = (isset($_REQUEST['id'])) ? __('Edit the Corner Ad', CORNER_AD_TD) : __('Create a new Corner Ad', CORNER_AD_TD);
        if(count($error)){
            $output .= '<div class="error settings-error">'.implode('<br />', $error).'</div>';
        }

        $output .=  '
                    <form action="options-general.php?page=corner-ad.php" method="post">     
                    <input type="hidden" name="corner_ad_edition_nonce" value="' . wp_create_nonce(__FILE__) . '" />
                    <input type="hidden" name="action" value="ad_save" />
                    '.((!empty($id)) ? '<input type="hidden" name="id" value="'.esc_attr($id).'">': '').'
                    <div class="postbox">
                        <h3 class="handle" style="padding:5px;"><span>'.$title.'</span></h3>
                        <div class="inside">
                            <table class="form-table">
								<tr valign="top">
									<th>'.__('Ad name', CORNER_AD_TD).'*</th>
									<td>
										<input type="text" name="corner_ad_name" size="40" value="'.((isset($corner_ad_name)) ? esc_attr($corner_ad_name) : '').'" />
									</td>
								</tr>
                            	<tr valign="top">
									<th>'.__('Enter Ad link', CORNER_AD_TD).'*</th>
									<td>
										<input type="text" name="corner_ad_adURL" size="40" value="'.((isset($corner_ad_adURL)) ? esc_attr($corner_ad_adURL) : '').'" />
									</td>
								</tr>
                                <tr valign="top">
									<th>'.__('Open Ad in', CORNER_AD_TD).'</th>
									<td>
                                        <select name="corner_ad_target">
                                            <option value="_blank" '.((isset($corner_ad_target) && $corner_ad_target == '_blank') ? 'SELECTED' : '').'>'.__('New page', CORNER_AD_TD).'</option>
                                            <option value="_self" '.((isset($corner_ad_target) && $corner_ad_target == '_self') ? 'SELECTED' : '').'>'.__('Self page', CORNER_AD_TD).'</option>
                                        </select>    
									</td>
								</tr>
                                <tr valign="top">
									<th>'.__('Select Ad image', CORNER_AD_TD).'*</th>
									<td>';
									
		$hasThumb = (!empty( $corner_ad_thumbPath ) && $corner_ad_thumbPath != $corner_ad_imgPath) ? true : false;
		
        $output .= '                 <div>    
                                        <input type="text" name="corner_ad_imgPath" size="40" value="'.((!empty($corner_ad_imgPath)) ? esc_attr($corner_ad_imgPath) : '').'" /> <input type="button" class="corner_ad_button_for_upload button" value="'.esc_attr(__('Browse', CORNER_AD_TD)).'" /> <input type="button" class="corner_ad_button_for_add_img_field button" value="Add another one" /> <input type="button" class="corner_ad_button_for_rmv_img_field button" value="Remove the image" DISABLED /><br />
										<input type="text" name="corner_ad_thumbPath" size="40" value="'.($hasThumb ? esc_attr($corner_ad_thumbPath) : '' ).'" placeholder="'.esc_attr(__( 'Thumbnail URL', CORNER_AD_TD)).'" '.(!$hasThumb ? 'style="display:none;"' : '' ).' /> <input type="button" class="corner_ad_button_for_upload button" value="'.esc_attr(__('Browse', CORNER_AD_TD)).'" '.(!$hasThumb ? 'style="display:none;"' : '' ).' /> <input type="checkbox" name="corner_ad_generateThum" '.(!$hasThumb ? 'CHECKED' : '' ).' class="corner_ad_thumb_chk" />'.__('Get the thumbnail of the Ad\'s image', CORNER_AD_TD).'
                                    </div>
                                    <tr valign="top">
									<th>'.__('Select an audio file to play in background', CORNER_AD_TD).'</th>
									<td>
										<input type="text" size="40" DISABLED /> <input type="button" value="'.esc_attr(__('Browse', CORNER_AD_TD)).'" DISABLED />
                                        The <a href="http://wordpress.dwbooster.com/content-tools/corner-ad" target="_blank">commercial version</a> of plugin allows to select an audio file to play in background.
                                    </td>
								</tr>
                                ';
            
        $output .=   '              </td>
								</tr>
                                <tr valign="top">
									<th>'.__('Set as mirror', CORNER_AD_TD).'</th>
									<td>
										<input type="checkbox" name="corner_ad_mirror" '.((!isset($corner_ad_mirror) || $corner_ad_mirror) ? 'checked' : '').' />									</td>
								</tr>
                                <tr valign="top">
									<th>'.__('Use corner with color', CORNER_AD_TD).'</th>
									<td>
                                        <input type="text" name="corner_ad_colorIn" id="corner_ad_colorIn" value="'.((isset($corner_ad_colorIn)) ? esc_attr($corner_ad_colorIn) : '#FFFFFF').'" style="background-color:'.((isset($corner_ad_colorIn)) ? esc_attr($corner_ad_colorIn) : '#FFFFFF').';" />
                                        <div id="corner_ad_colorIn_picker"></div>
									</td>
								</tr>
                                <tr valign="top">
									<th>'.__('Display Ad in corner', CORNER_AD_TD).'</th>
									<td>
                                        <select name="corner_ad_alignTo" DISABLED>
                                            <option value="tl">'.__('Top-Left', CORNER_AD_TD).'</option>
                                        </select>    
                                        The free version of plugin allows to display the Ad only in the Left-Top corner only. The <a href="http://wordpress.dwbooster.com/content-tools/corner-ad" target="_blank">commercial version</a> allows to select between the Left or Right top corner.
									</td>
								</tr>
                                <tr valign="top">
									<th>'.__('Open corner in', CORNER_AD_TD).'</th>
									<td><input type="text" name="corner_ad_openIn" value="'.((isset($corner_ad_openIn) && $corner_ad_openIn >0) ? esc_attr($corner_ad_openIn) : '' ).'">'.__('Seconds', CORNER_AD_TD).'
									</td>
								</tr>
                                <tr valign="top">
									<th>'.__('Close corner in', CORNER_AD_TD).'</th>
									<td><input type="text" name="corner_ad_closeIn" value="'.((isset($corner_ad_closeIn) && $corner_ad_closeIn > 0) ? esc_attr($corner_ad_closeIn) : '' ).'">'.__('Seconds', CORNER_AD_TD).'
									</td>
								</tr>
                                <tr valign="top">
									<td colspan="2" align="middle"><input type="submit" value="'.esc_attr(__('Save Corner Ad', CORNER_AD_TD)).'" class="button-primary" /> <a href="options-general.php?page=corner-ad.php" class="button">'.__('Back to the list', CORNER_AD_TD).'</a></td>
								</tr>
                            </table>    
                        </div>
                    </div>    
                    </form>
                    <script>
                        jQuery(function(){
                            jQuery("#corner_ad_colorIn_picker").hide();
                            jQuery("#corner_ad_colorIn_picker").farbtastic("#corner_ad_colorIn");
                            jQuery("#corner_ad_colorIn").click(function(){jQuery("#corner_ad_colorIn_picker").slideToggle()});
	                    });
                    </script>
                   ';
        return $output;
    } // End corner_ad_settings_page_form
}

if (!function_exists('corner_ad_get_images')){
	function corner_ad_process_images( &$obj, $size = 'large' )
	{
        global $wpdb;
		if(preg_match('/attachment_id=(\d+)/', $obj->url, $matches)) $obj->id = $matches[1];
        else{
            $id = $wpdb->get_var($wpdb->prepare("SELECT id FROM ".$wpdb->prefix."posts WHERE guid='%s'", $obj->url));
            if($id) $obj->id = $id;
		}
		
		if( !empty( $obj->id ) )
		{
			$resized = wp_get_attachment_image_src( $obj->id, $size );
			$obj->url = $resized[0];
		}	
	} // End corner_ad_process_images
	
    function corner_ad_get_images($url, $thumbUrl, $to_show = false ){
        $img = new stdClass;
        $img->thumb = new stdClass;
		$img->large = new stdClass;
        $img->thumb->url = ( !empty($thumbUrl) ) ? $thumbUrl : $url;
        $img->large->url = $url;
		corner_ad_process_images( $img->thumb, $to_show ? 'corner_ad_thumb' : 'large' );
		corner_ad_process_images( $img->large, $to_show ? 'corner_ad' : 'large' );
		return $img;
    } // End corner_ad_get_images
}
?>