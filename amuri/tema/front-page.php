<?php
/**
 * The template for homepage
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

 if ( ! is_user_logged_in() ) { wp_redirect( get_permalink( get_option('woocommerce_myaccount_page_id') ) ); }
else {
    wp_redirect( get_permalink( 167 ) );
}