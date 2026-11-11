<?php
global $post;
$post_id = $post->ID;
$user_can_access = true;
if ( 'lesson' == get_post_type( $post_id ) ) {
    $lesson_id = $post_id;
    if ( get_post_meta( $lesson_id, '_lesson_course', true ) ) {
        $post_id = get_post_meta( $lesson_id, '_lesson_course', true );
        if ( function_exists('wc_memberships_user_can') && ! wc_memberships_user_can( get_current_user_id(), 'view', array( 'course' => $post_id ) ) ) {
            $user_can_access = false;
        }
        
    }
}
if ( 'page' == get_post_type( $post_id ) && function_exists('wc_memberships_user_can') ) {
    if ( ! wc_memberships_user_can( get_current_user_id(), 'view', array( 'page' => $post_id ) ) ) {
        wp_redirect( get_bloginfo('home') );
    }
}