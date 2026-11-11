<?php
/**
 * The template for displaying the header
 *
 * Displays all of the head element and everything up until the "site-content" div.
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

?><!DOCTYPE html>
<html <?php language_attributes(); ?> data-is-mobile="<?php echo wp_is_mobile(); ?>">
<head>

    <?php
        // Google Analytics - código de monitoramento
        if ( ! is_user_logged_in() && 'production' == AMBIENT_VAR_DEF ) {
    ?>

    <?php
        } // if ( ! is_user_logged_in() && 'production' == AMBIENT_VAR_DEF ) {
    ?>

    <meta charset="<?php bloginfo( 'charset' ); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="profile" href="http://gmpg.org/xfn/11">
    <?php if ( is_singular() && pings_open( get_queried_object() ) ) : ?>
    <link rel="pingback" href="<?php bloginfo( 'pingback_url' ); ?>">
    <?php endif; ?>
    <meta content="telephone=no" name="format-detection">

    <?php wp_head(); ?>

</head>

<body <?php body_class('font-sans bg-white text-black-med'); ?> data-is-mobile="<?php echo wp_is_mobile(); ?>">
    <?php do_action('after_body'); ?>

    <div id="top"></div>

    <div id="page">

    <?php
    if ( is_checkout() || is_wc_endpoint_url('order-received') ) {
    ?>
        
    <div class="header-logo">
        <img class="logo-image" src="<?php echo public_url(); ?>images/logo-amuri.png" width="589" height="389" alt="">
    </div>

    <?php
        if ( is_checkout() && ! is_wc_endpoint_url('order-received') && ! is_wc_endpoint_url('order-pay') ) {
    ?>
    <div class="checkout-container">
        <h1 class="typog-title"><?php esc_attr_e('Preencha os dados abaixo, por favor :)','amrwp'); ?></h1>
    </div>
    <!-- /.checkout-container -->
    <?php
        }
    }
    ?>