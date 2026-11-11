<?php
/**
 * Configurações do tema
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

if ( ! isset( $content_width ) ) $content_width = 940;

if ( ! function_exists( 'public_url' ) ):

    function public_url() {

        // if ( 'production' == AMBIENT_VAR_DEF ) {
        //     return get_bloginfo('template_directory') . '/public/min/';
        // } else {
            return get_bloginfo('template_directory') . '/public/';
        // }
    }

endif; // if ( ! function_exists( 'public_url' ) {

if ( ! function_exists( 'assets_url' ) ):

    function assets_url() {
        return get_bloginfo('template_directory') . '/public/';
    }

endif; // if ( ! function_exists( 'assets_url' ) {

/** 
 ** Setup inicial do tema
**/

if ( ! function_exists( 'amrwp_setup_inicial' ) ):

function amrwp_setup_inicial() {
    global $curso_configurations;
    /*
     * Inicia a traducao
     */
    load_theme_textdomain( 'amrwp', get_template_directory() . '/languages' );

    /*
     * Let WordPress manage the document title.
     * By adding theme support, we declare that this theme does not use a
     * hard-coded <title> tag in the document head, and expect WordPress to
     * provide it for us.
     */
    add_theme_support( 'title-tag' );

    // This theme uses wp_nav_menu() in two locations.
    register_nav_menus( array(
        'curso-dsm' => __( 'Dinheiro sem medo', 'amrwp' ),
        'curso-fpa' => __( 'Finanças para autônomos', 'amrwp' ),
        'user-menu' => __( 'Menu do usuário', 'amrwp' ),
    ) );

    /*
     * Switch default core markup for search form, comment form, and comments
     * to output valid HTML5.
     */
    add_theme_support( 'html5', array(
      'search-form',
      'comment-form',
      'comment-list',
      'gallery',
      'caption',
    ) );

    /*
     * This theme styles the visual editor to resemble the theme style,
     * specifically font, colors, icons, and column width.
     */
    add_editor_style( 'assets/css/editor-style.css' );

    /*
     * Seta os tamanhos das imagens
     */
    add_theme_support( 'post-thumbnails' );
    add_image_size( 'curso-banner', 1365, 545, false ); // width, height, crop

    add_theme_support( 'sensei' );

}
endif; // if ( ! function_exists( 'amrwp_setup_inicial' ) ) {
add_action( 'after_setup_theme', 'amrwp_setup_inicial' );

/**
 * Enqueues scripts and styles for front-end.
 *
 * @since Amuri Plataforma 1.0
 */
function amrwp_scripts_styles() {
    global $wp_styles;
    global $post;

    $cssVer = '1.0.48';
    $jsVer = '1.0.48';

    if ( is_singular( 'lesson' ) || is_page_template('page-programa-plantoes.php') ) {
        wp_enqueue_style( 'mCustomScrollbar-amrwp-style', public_url() . 'js/plugins/mCustomScrollbar/jquery.mCustomScrollbar.min.css', '' , $cssVer );
    }

    if ( is_page_template('page-programa-plantoes.php') ) {
        wp_enqueue_style( 'jquery-ui-amrwp-style', '//code.jquery.com/ui/1.13.2/themes/base/jquery-ui.css', '' , $cssVer );
    }

    /*
     * Carrega os CSS's comuns
     */
    wp_enqueue_style( 'global-amrwp-style', public_url() . 'css/global.css', '' , $cssVer );

    /*
     * Adiciona o global.js
     */

     $translation_placeholder = array(
        'amrwp_LoginFormUsernamePlaceholder' => __( 'Preencha com seu e-mail', 'amrwp' ), // variable for username placeholder
        'amrwp_LoginFormPasswordPlaceholder' => __( 'Preencha com sua senha', 'amrwp' ), // variable for password placeholder
        'amrwp_FinishLessonGoToNextLessons' => __( 'Finalizar e começar próxima aula', 'amrwp' ), // variable for finish lesson
      );
      
    if ( is_page_template('page-editar-perfil.php') ) {
    
        wp_register_script( 'jquery-maskedinput-amrwp-scripts', public_url() . 'js/plugins/jquery.maskedinput/jquery.maskedinput.min.js', array('jquery'), $jsVer, true );
        wp_enqueue_script( 'jquery-maskedinput-amrwp-scripts' );

    }

    
    if ( is_page_template('page-lp-dsm.php') ) {
        wp_register_script( 'slick-amrwp-scripts', public_url() . 'js/plugins/slick/slick.min.js', array('jquery'), $jsVer, true );
        wp_enqueue_script( 'slick-amrwp-scripts' );
    }
      
    if ( is_page_template('page-painel-programa.php') ) {
    
        wp_register_script( 'audio-player-amrwp-scripts', public_url() . 'js/audio-player.js', array('jquery'), $jsVer, true );
        wp_enqueue_script( 'audio-player-amrwp-scripts' );
        
        wp_register_script( 'slick-amrwp-scripts', public_url() . 'js/plugins/slick/slick.min.js', array('jquery'), $jsVer, true );
        wp_enqueue_script( 'slick-amrwp-scripts' );

    }
      
    if ( is_page_template('page-programa-plantoes.php') ) {
        
        wp_register_script( 'slick-amrwp-scripts', public_url() . 'js/plugins/slick/slick.min.js', array('jquery'), $jsVer, true );
        wp_enqueue_script( 'slick-amrwp-scripts' );

        wp_register_script( 'jquery-ui-amrwp-scripts', 'https://code.jquery.com/ui/1.13.2/jquery-ui.js', array('jquery'), $jsVer, true );
        wp_enqueue_script( 'jquery-ui-amrwp-scripts' );

        wp_register_script( 'jquery-ui-pt-br-amrwp-scripts', public_url() . 'js/plugins/jquery-ui/datepicker-pt-BR.js', array('jquery'), $jsVer, true );
        wp_enqueue_script( 'jquery-ui-pt-br-amrwp-scripts' );

    }
      
    if ( is_singular( 'amr_plantao' ) || is_page_template('page-programa-plantoes.php') ) {
    
        wp_register_script( 'jquery-fitvids-scripts', public_url() . 'js/plugins/jquery.fitvids/jquery.fitvids.js', array('jquery'), $jsVer, true );
        wp_enqueue_script( 'jquery-fitvids-scripts' );
        
    }
      
    if ( is_singular( 'lesson' ) || is_page_template('page-programa-plantoes.php') ) {
    
        wp_register_script( 'mCustomScrollbar-amrwp-scripts', public_url() . 'js/plugins/mCustomScrollbar/jquery.mCustomScrollbar.concat.min.js', array('jquery'), $jsVer, true );
        wp_enqueue_script( 'mCustomScrollbar-amrwp-scripts' );
        
    }

    wp_register_script( 'global-amrwp-scripts', public_url() . 'js/global.js', '', $jsVer, true );
    wp_localize_script( 'global-amrwp-scripts', 'amrwp_placeHolderForLoginForm', $translation_placeholder ); // hook wp_localize_script
    wp_localize_script( 'global-amrwp-scripts', 'amrwp_Ajax', array( 'amrwp_AjaxURL' => admin_url( 'admin-ajax.php' )));
    wp_enqueue_script( 'global-amrwp-scripts' );
    
    
} // function amrwp_scripts_styles() {

add_action( 'wp_enqueue_scripts', 'amrwp_scripts_styles' );

// Move Yoast box to bottom
if ( ! function_exists('amrwp_yoasttobottom') ) {
function amrwp_yoasttobottom() {
    return 'low';
}
add_filter( 'wpseo_metabox_prio', 'amrwp_yoasttobottom');
} // if ( ! function_exists('amrwp_yoasttobottom') ) {

// Change the Admin Login Logo
// https://codex.wordpress.org/Customizing_the_Login_Form
if ( ! function_exists('amrwp_my_login_logo') ) {
function amrwp_my_login_logo() { ?>
    <style type="text/css">
        #login h1 a {
            background: url(<?php echo get_stylesheet_directory_uri(); ?>/public/images/logo-amuri.png) center center no-repeat;
              width: 100%; height: 140px; background-size: auto 100%; margin-bottom: 10px;
        }
    </style>
<?php }
add_action( 'login_enqueue_scripts', 'amrwp_my_login_logo' );
} // if ( ! function_exists('amrwp_my_login_logo') ) {

if ( ! function_exists('amrwp_login_custom_link') ) {
function amrwp_login_custom_link() {
    return get_bloginfo('url');
}
add_filter('login_headerurl','amrwp_login_custom_link');
} // if ( ! function_exists('amrwp_login_custom_link') ) {

if ( ! function_exists('amrwp_login_title_on_logo') ) {
function amrwp_login_title_on_logo() {
    return get_bloginfo('name');
}
add_filter('login_headertext', 'amrwp_login_title_on_logo');
} // if ( ! function_exists('amrwp_login_title_on_logo') ) {
    
// Allow SVG through WordPress Media Uploader
// https://css-tricks.com/snippets/wordpress/allow-svg-through-wordpress-media-uploader/
function amrwp_cc_mime_types($mimes) {
    $mimes['svg'] = 'image/svg+xml';
    return $mimes;
}
add_filter('upload_mimes', 'amrwp_cc_mime_types');

/**
 * Disable the emoji's
 */
function disable_emojis() {
    remove_action( 'wp_head', 'print_emoji_detection_script', 7 );
    remove_action( 'admin_print_scripts', 'print_emoji_detection_script' );
    remove_action( 'wp_print_styles', 'print_emoji_styles' );
    remove_action( 'admin_print_styles', 'print_emoji_styles' ); 
    remove_filter( 'the_content_feed', 'wp_staticize_emoji' );
    remove_filter( 'comment_text_rss', 'wp_staticize_emoji' ); 
    remove_filter( 'wp_mail', 'wp_staticize_emoji_for_email' );
    add_filter( 'tiny_mce_plugins', 'disable_emojis_tinymce' );
    add_filter( 'wp_resource_hints', 'disable_emojis_remove_dns_prefetch', 10, 2 );
   }
   add_action( 'init', 'disable_emojis' );
   
   /**
    * Filter function used to remove the tinymce emoji plugin.
    * 
    * @param array $plugins 
    * @return array Difference betwen the two arrays
    */
   function disable_emojis_tinymce( $plugins ) {
    if ( is_array( $plugins ) ) {
    return array_diff( $plugins, array( 'wpemoji' ) );
    } else {
    return array();
    }
   }
   
   /**
    * Remove emoji CDN hostname from DNS prefetching hints.
    *
    * @param array $urls URLs to print for resource hints.
    * @param string $relation_type The relation type the URLs are printed for.
    * @return array Difference betwen the two arrays.
    */
   function disable_emojis_remove_dns_prefetch( $urls, $relation_type ) {
    if ( 'dns-prefetch' == $relation_type ) {
    /** This filter is documented in wp-includes/formatting.php */
    $emoji_svg_url = apply_filters( 'emoji_svg_url', 'https://s.w.org/images/core/emoji/2/svg/' );
   
   $urls = array_diff( $urls, array( $emoji_svg_url ) );
    }
   
   return $urls;
}

if ( ! function_exists('amrwp_wc_custom_user_redirect') ):
function amrwp_wc_custom_user_redirect( $redirect, $user ) {

    $my_courses = get_permalink( get_page_by_path( 'meus-programas' ) );

    $role = $user->roles[0];
    $dashboard = admin_url();
    if( $role == 'administrator' ) {
      //Redirect administrators to the dashboard
      $redirect = $dashboard;
    } elseif ( $role == 'shop-manager' ) {
      //Redirect shop managers to the dashboard
      $redirect = $dashboard;
    } elseif ( $role == 'editor' ) {
      //Redirect editors to the dashboard
      $redirect = $dashboard;
    } elseif ( $role == 'author' ) {
      //Redirect authors to the dashboard
      $redirect = $dashboard;
    } elseif ( $role == 'customer' || $role == 'subscriber' && isset($my_courses) ) {
      //Redirect customers and subscribers to the "My Account" page
      $redirect = $my_courses;
    } else {
      //Redirect any other role to the previous visited page or, if not available, to the home
      $redirect = wp_get_referer() ? wp_get_referer() : home_url();
    }
    return $redirect;
  }
add_filter( 'woocommerce_login_redirect', 'amrwp_wc_custom_user_redirect', 10, 2 ); 
endif; // if ( ! function_exists('amrwp_wc_custom_user_redirect') ):

if ( ! function_exists('amrwp_wc_form_login_change') ):
add_filter( 'gettext', 'amrwp_wc_form_login_change', 20, 3 );
function amrwp_wc_form_login_change( $translated_text, $text, $domain ) 
    {
        if ($text === 'Remember me') 
        {
            $translated_text = __('Lembrar dos dados','amrwp');
        }
        if ($text === 'Log in') 
        {
            $translated_text = __('Entrar','amrwp');
        }
        if ($text === 'Lost your password?') 
        {
            $translated_text = __('Esqueci a senha','amrwp');
        }
        return $translated_text;
}
endif; // if ( ! function_exists('amrwp_wc_form_login_change') ):

if ( ! function_exists('amrwp_change_page_menu_classes') ):
// Custom post type active menu item - CPT amr_atalho
// https://stackoverflow.com/questions/28139044/custom-post-type-active-menu-item 
function amrwp_change_page_menu_classes($menu)
{
    global $post;
    if ( is_search() ) return $menu;

    if (get_post_type($post) == 'amr_atalho') {
        $menu = str_replace( array('menu-item-229','menu-item-266'), array('menu-item-229 current-menu-item','menu-item-266 current-menu-item'), $menu ); // add the current_page_parent class to the page you want
    }
    if (get_post_type($post) == 'amr_plantao') {
        $menu = str_replace( array('menu-item-238','menu-item-269'), array('menu-item-238 current-menu-item','menu-item-269 current-menu-item'), $menu ); // add the current_page_parent class to the page you want
    }
    if (get_post_type($post) == 'lesson') {
        $menu = str_replace( array('menu-item-232', 'menu-item-288'), array('menu-item-232 current-menu-item','menu-item-288 current-menu-item'), $menu ); // add the current_page_parent class to the page you want
    }
    return $menu;
}
add_filter( 'nav_menu_css_class', 'amrwp_change_page_menu_classes', 10,2 );
endif; // if ( ! function_exists('amrwp_change_page_menu_classes') ):

if ( ! function_exists('amrwp_my_custom_css') ):
function amrwp_my_custom_css() {
?>
<style>
    .wp-admin-acf-field-lesson-duration .acf-fields {
        display: flex;
    } 
</style>
<?php
}
add_action('admin_head', 'amrwp_my_custom_css');
endif; // if ( ! function_exists('amrwp_my_custom_css') ):

if ( ! function_exists('amrwp_empty_wc_add_to_cart_message') ):
function amrwp_empty_wc_add_to_cart_message() { 
    return ''; 
}
add_filter( 'wc_add_to_cart_message_html', 'amrwp_empty_wc_add_to_cart_message');
endif; // if ( ! function_exists('amrwp_empty_wc_add_to_cart_message') ):

add_filter( 'woocommerce_enable_order_notes_field', '__return_false', 9999 );

add_filter( 'woocommerce_order_button_text', function() {
    return 'Quero me matricular agora!';
} );

/**
 * Insert an empty notice container right above the "place order" button so
 * that submission errors (invalid card, no balance, etc.) render next to the
 * action the customer just took, instead of at the top of the form.
 */
add_action( 'woocommerce_review_order_before_submit', function() {
    echo '<div id="amrwp-checkout-error-target"></div>';
} );

function amrwp_wc_custom_override_checkout_fields( $fields ) {
    $fields['address_1']['placeholder'] = '';
    $fields['address_2']['placeholder'] = '';
    $fields['address_2']['label'] = 'Complemento';
    return $fields;
  }
add_filter( 'woocommerce_default_address_fields' , 'amrwp_wc_custom_override_checkout_fields' ); 

function amrwp_wc_custom_text_replace( $translated_text, $untranslated_text, $domain ) {
    if ( 'Pay with PIX' == $untranslated_text ) {
        $translated_text = 'Pagar com Pix';
    }
    if ( 'Use with default' == $untranslated_text ) {
        $translated_text = 'Usar como padrão';
    }
    if ( 'After clicking on "Place order", you will have access to the QR Code, which you can read with your payment app.' == $untranslated_text ) {
        $translated_text = 'Ao clicar em "Finalizar pedido", você terá acesso ao QR Code e poderá concluir seu pagamento.';
    }
    return $translated_text;
}
add_filter( 'gettext', 'amrwp_wc_custom_text_replace', 20, 3 );

/* 
 * WooCommerce Hide "You cannot add another "XXX" to your cart."
 */
function amrwp_wc_cart_product_cannot_add_another_message( $message, $product_data ) {    
    $message = '<div class="hide-this-error-message"></div>';
    
    return $message;
}
add_filter( 'woocommerce_cart_product_cannot_add_another_message', 'amrwp_wc_cart_product_cannot_add_another_message', 10, 2 );

function amrwp_wc_wp_footer() {
    ?>
    <script>
        jQuery(document).ready(function($) {
            $( '.hide-this-error-message' ).closest( 'ul.woocommerce-error' ).hide();

            // Move WC checkout error notice from the top of the form to the
            // dedicated container right above the place_order button.
            $(document.body).on('checkout_error', function() {
                setTimeout(function() {
                    var $notice = $('form.checkout > .woocommerce-NoticeGroup-checkout').first();
                    var $target = $('#amrwp-checkout-error-target');
                    if ($notice.length && $target.length) {
                        $target.empty().append($notice);
                        $('html, body').animate({
                            scrollTop: $target.offset().top - 120
                        }, 400);
                    }
                }, 50);
            });

            // Iugu CC plugin runs client-side validation (Iugu.createPaymentToken)
            // before WC submit, and injects <div class="woocommerce-error"> into
            // #iugu-credit-card-fields directly — bypassing the checkout_error
            // event. Watch for it and move into the dedicated container.
            // Observing form.checkout (stable) instead of #payment because WC
            // re-renders #payment on update_checkout, detaching the old observer.
            var formNode = document.querySelector('form.checkout');
            if (formNode && window.MutationObserver) {
                var moveIuguError = function() {
                    var $err = $('#iugu-credit-card-fields > .woocommerce-error').first();
                    var $target = $('#amrwp-checkout-error-target');
                    if ($err.length && $target.length) {
                        $target.empty().append($err);
                        $('html, body').animate({
                            scrollTop: $target.offset().top - 120
                        }, 400);
                    }
                };
                new MutationObserver(moveIuguError).observe(formNode, {
                    childList: true,
                    subtree: true
                });
            }
        });
    </script>
    <?php
}
add_action( 'wp_footer', 'amrwp_wc_wp_footer' );

/* Remove Sensei courses links in Woocommerce orders */
add_action( 'init', 'amrwp_wc_remove_courses_links' );
function amrwp_wc_remove_courses_links () {
    remove_action( 'woocommerce_email_after_order_table', [ 'Sensei_WC', 'email_course_details' ], 10, 1 );
}

/**
 * Force the cart to contain exclusively the product whose ID is in the URL
 * (?id=NNN) whenever the customer hits the checkout page. Used because this
 * checkout is built to sell a single product at a time.
 */
add_action( 'template_redirect', 'amrwp_checkout_force_single_product_from_url', 5 );
function amrwp_checkout_force_single_product_from_url() {
    if ( is_admin() || wp_doing_ajax() || ! function_exists( 'is_checkout' ) ) {
        return;
    }
    if ( ! is_checkout() || is_wc_endpoint_url() ) {
        return;
    }
    if ( empty( $_GET['id'] ) ) {
        return;
    }

    $product_id = absint( wp_unslash( $_GET['id'] ) );
    if ( $product_id <= 0 ) {
        return;
    }

    $product = wc_get_product( $product_id );
    if ( ! $product || ! $product->is_purchasable() ) {
        return;
    }

    $cart = WC()->cart;
    if ( ! $cart ) {
        return;
    }

    $cart->empty_cart();
    $cart->add_to_cart( $product_id, 1 );
    $cart->calculate_totals();
}