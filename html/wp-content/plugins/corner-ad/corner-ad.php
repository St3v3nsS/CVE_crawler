<?php
/*
Plugin Name: Corner Ad
Plugin URI: http://wordpress.dwbooster.com/content-tools/music-store
Description: Corner Ad is a minimally invasive advertising display that uses any of your webpage's top corners - a position typically under-utilized by developers - and attracts users' attention by a cool visual effect imitating a page flip
Version: 1.0.7
Author: CodePeople
Author URI: http://www.codepeople.net
License: GPLv2
*/

// CONST
define('CORNER_AD_PLUGIN_DIR', dirname(__FILE__));
define('CORNER_AD_PLUGIN_URL', plugins_url('', __FILE__));
define('CORNER_AD_TD', 'corner_ad_text_domain');
define('CORNER_AD_TABLE', 'corner_ad');
define('CORNER_AD_IMG_TABLE', 'corner_ad_img');

include CORNER_AD_PLUGIN_DIR.'/includes/admin_functions.php';
/**
* Plugin activation
*/
register_activation_hook( __FILE__, 'corner_ad_install' );
if(!function_exists('corner_ad_install')){        
	function _corner_ad_install() {
        global $wpdb;
        
        // Create related table
        $sql = "
                CREATE TABLE IF NOT EXISTS ".$wpdb->prefix.CORNER_AD_TABLE."
                (id MEDIUMINT(9) NOT NULL AUTO_INCREMENT,
                name VARCHAR(250) NOT NULL DEFAULT '',
                alignTo CHAR(2) NOT NULL DEFAULT 'tr',
                mirror TINYINT(1) NOT NULL DEFAULT 1,
                colorIn VARCHAR(7) NOT NULL DEFAULT 'FFFFFF',
                openIn INT NOT NULL DEFAULT 5,
                closeIn INT NOT NULL DEFAULT 5,
                adURL VARCHAR(250) NOT NULL DEFAULT '',
                target VARCHAR(50) NOT NULL DEFAULT '_blank',
                stat INT NOT NULL DEFAULT 0,
                PRIMARY KEY id (id)
                );
               ";
		$wpdb->query($sql);
        
        // Create related table
        $sql = "
                CREATE TABLE IF NOT EXISTS ".$wpdb->prefix.CORNER_AD_IMG_TABLE."
                (id MEDIUMINT(9) NOT NULL AUTO_INCREMENT,
                ad MEDIUMINT(9) NOT NULL,
                imgPath VARCHAR(255) NOT NULL,
                thumbPath VARCHAR(255) NULL,
                PRIMARY KEY id (id)
                );
               ";
		$wpdb->query($sql);
        
		$result = $wpdb->get_results("SHOW COLUMNS FROM ".$wpdb->prefix.CORNER_AD_IMG_TABLE." LIKE 'thumbPath'");
        if(empty($result)){
            $sql = "ALTER TABLE ".$wpdb->prefix.CORNER_AD_IMG_TABLE." ADD thumbPath VARCHAR(255) NULL";
            $wpdb->query($sql);
        }
        // Set the image size required by the corner_ad 
        //add_image_size( 'corner_ad', 300, 300, true );
    } // End +corner_ad_install
	
	function corner_ad_install( $network_wide ) {
		global $wpdb;	
		if( function_exists( 'is_multisite' ) && is_multisite() ) 
		{
			// check if it is a network activation - if so, run the activation function for each blog id
			if ($network_wide) 
			{
	            $current_blog = $wpdb->blogid;
				// Get all blog ids
				$blog_ids = $wpdb->get_col( "SELECT blog_id FROM $wpdb->blogs" );
				foreach ( $blog_ids as $blog_id ) 
				{
					switch_to_blog( $blog_id );
					_corner_ad_install();
				}
				switch_to_blog( $current_blog );
				return;
			}
		}
		_corner_ad_install();
    } // End corner_ad_install
} // End plugin activation

// A new blog has been created in a multisite WordPress
add_action( 'wpmu_new_blog', 'corner_ad_new_blog', 10, 6);        
 
function corner_ad_new_blog($blog_id, $user_id, $domain, $path, $site_id, $meta ) {
    global $wpdb;
	if ( is_plugin_active_for_network() ) 
	{
        $current_blog = $wpdb->blogid;
        switch_to_blog( $blog_id );
        _corner_ad_install();
        switch_to_blog( $current_blog );
    }
}

/*
*   Plugin initializing
*/
add_action( 'init', 'corner_ad_init');
if(!function_exists('corner_ad_init')){
    function corner_ad_init(){
        // Set the add shortcode
        add_shortcode('corner-ad', 'corner_ad_replace_shortcode');
        add_image_size( 'corner_ad_thumb', 100, 100, true );
        add_image_size( 'corner_ad', 500, 500, true );
    } // End corner_ad_init
}

/*
*   Admin initionalizing
*/
add_action('admin_init', 'corner_ad_admin_init');
if(!function_exists('corner_ad_admin_init')){
    function corner_ad_admin_init(){
        // Load the associated text domain
        load_plugin_textdomain( CORNER_AD_TD, false, CORNER_AD_PLUGIN_DIR . '/languages/' );	
        
        // Set plugin links
        $plugin = plugin_basename(__FILE__);
        add_filter('plugin_action_links_'.$plugin, 'corner_ad_links');
        
        // Set a new media button for corner ad insertion
        add_action('media_buttons', 'corner_ad_media_button', 100);
    } // End corner_ad_admin_init
}

if(!function_exists('corner_ad_links')){
    function corner_ad_links($links){
        // Custom link
        $custom_link = '<a href="http://wordpress.dwbooster.com/contact-us" target="_blank">'.__('Request custom changes', CORNER_AD_TD).'</a>'; 
		array_unshift($links, $custom_link); 
        
        // Settings link
        $settings_link = '<a href="options-general.php?page=corner-ad.php">'.__('Settings').'</a>'; 
		array_unshift($links, $settings_link); 
        
		return $links; 
    } // End corner_ad_customization_link
}

// Set the settings menu option
add_action('admin_menu', 'corner_ad_settings_menu');
if(!function_exists('corner_ad_settings_menu')){
    function corner_ad_settings_menu(){
        // Add to admin_menu
		add_options_page('Corner AD', 'Corner AD', 'edit_posts', basename(__FILE__), 'corner_ad_settings_page'); 
    } // End corner_ad_settings_menu
}

if(!function_exists('corner_ad_settings_page')){
    function corner_ad_settings_page(){
        global $wpdb;
		wp_enqueue_media();
?>
        <div class="wrap">
            <h1><?php _e('Corner Ad', CORNER_AD_TD); ?></h1>
<?php
        if(isset($_REQUEST['action'])){
            switch($_REQUEST['action']){
                case 'ad_remove':
                    if(isset($_REQUEST['id'])){
                        if($wpdb->query($wpdb->prepare("DELETE FROM ".$wpdb->prefix.CORNER_AD_IMG_TABLE." WHERE ad=%d", $_REQUEST['id']))){
                            $wpdb->query($wpdb->prepare("DELETE FROM ".$wpdb->prefix.CORNER_AD_TABLE." WHERE id=%d", $_REQUEST['id']));
                        }
                    }
                    print corner_ad_settings_page_list();
                break;
                case 'ad_edit':
                case 'ad_create':
                    print corner_ad_settings_page_form();
                break;
                case 'ad_save':
                    print corner_ad_settings_page_form();
                break;
                default:
                    print corner_ad_settings_page_list();
                break;
            }
        }else{
            print corner_ad_settings_page_list();
        }
        
?>
        </div>    
<?php        
    } // End corner_ad_settings_page
}

if(!function_exists('corner_ad_replace_shortcode')){
    function corner_ad_replace_shortcode($attr){
        global $wpdb, $corner_ad_inserted;
        
        
        if(isset($attr['id']) && !isset($corner_ad_inserted)){
            $ad = $wpdb->get_row($wpdb->prepare("SELECT * FROM ".$wpdb->prefix.CORNER_AD_TABLE." WHERE id=%d", $attr['id']));
            if($ad){
				$corner_ad_inserted = true;
                // Enqueue required files
				wp_enqueue_script( 'jquery' );
                wp_enqueue_script( 'corner_ad_raphael_script',  CORNER_AD_PLUGIN_URL.'/js/raphael-min.js');
                wp_enqueue_script( 'corner_ad_public_script',  CORNER_AD_PLUGIN_URL.'/js/cornerAd.min.js', array( 'jquery', 'corner_ad_raphael_script' ));
                
                // Select the image
                $row = $wpdb->get_row($wpdb->prepare("SELECT imgPath, thumbPath FROM ".$wpdb->prefix.CORNER_AD_IMG_TABLE." WHERE ad=%d", $ad->id));

                if($row){
                    $img = corner_ad_get_images($row->imgPath, ((!empty($row->thumbPath))? $row->thumbPath: '' ), true);
                }

                $colorIn = $ad->colorIn;
				return "<script>if(window.addEventListener){ window.addEventListener('load', function(){ printCornerAd({alignTo:'tl', mirror:".esc_js(($ad->mirror == 1) ? 'true' : 'false').", colorIn:'".esc_js($colorIn)."', thumbPath:'".esc_js($img->thumb->url)."', imgPath:'".esc_js($img->large->url)."', adUrl:'".esc_js($ad->adURL)."', openIn:".esc_js(($ad->openIn) ? $ad->openIn : -1).", closeIn:".esc_js(($ad->closeIn) ? $ad->closeIn : -1).", target:'".esc_js($ad->target)."'}); }); }else{ window.attachEvent('onload', function(){ printCornerAd({alignTo:'tl', mirror:".esc_js(($ad->mirror == 1) ? 'true' : 'false').", colorIn:'".esc_js($colorIn)."', thumbPath:'".esc_js($img->thumb->url)."', imgPath:'".esc_js($img->large->url)."', adUrl:'".esc_js($ad->adURL)."', openIn:".esc_js(($ad->openIn) ? $ad->openIn : -1).", closeIn:".esc_js(($ad->closeIn) ? $ad->closeIn : -1).", target:'".esc_js($ad->target)."'}); }); } </script>";
            }    
        }    
        
        return '';
    } // End corner_ad_replace_shortcode
} 

if(!function_exists('corner_ad_media_button')){
    function corner_ad_media_button(){
        global $wpdb;
        
        // Enqueue required files
        wp_enqueue_style('wp-jquery-ui-dialog');
		wp_enqueue_script('corner_ad_insertion', CORNER_AD_PLUGIN_URL.'/js/ca-insertion.js', array('jquery', 'jquery-ui-dialog'));
        
        $ads = $wpdb->get_results("SELECT id, name FROM ".$wpdb->prefix.CORNER_AD_TABLE." ORDER BY name ASC;");
        $list = '';
        if($ads){
            foreach($ads as $ad){
                $list .= '<option value="'.esc_attr($ad->id).'">'.$ad->name.'</option>';
            }
        }
        
        wp_localize_script('corner_ad_insertion', 'corner_ad', array('list' => $list));
        
        print '<a href="javascript:open_insertion_corner_ad_window();" title="'.esc_attr(__('Insert Corner Ad')).'"><img src="'.esc_url(CORNER_AD_PLUGIN_URL.'/images/corner-ad-icon.gif').'" alt="'.esc_attr(__('Insert Corner Ad')).'" /></a>';
    } // End corner_ad_media_button
}
?>