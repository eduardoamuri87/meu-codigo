<?php
/**
 * Template name: Meus Programas
 * Página com listagem dos cursos
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */
if ( ! is_user_logged_in() ) wp_redirect( get_permalink( get_option('woocommerce_myaccount_page_id') ) );
 
get_header('curso');
?>

<h1 class="font-sans-black typog-title uppercase leading-[1em] text-center mb-[40px] mxlg:px-[40px]"><?php the_title(); ?></h1>

<?php include_once('includes/header-user-menu.php'); ?>

<?php
$courses_qry = new WP_Query(array(
    'post_type' => 'course',
    'posts_per_page' => -1,
    'orderby' => 'menu_order',
    'order' => 'ASC'
));

if ( $courses_qry->have_posts() ): 
?>
<div class="wp-programas-acompanhamento">
    <?php
    while ( $courses_qry->have_posts() ): $courses_qry->the_post();
        $post = get_post( get_the_ID() );

        $pages_pgms = get_posts(array(
            'numberposts' => 1,
            'post_type' => 'page',
            'meta_key' => 'pgm_crs_rlcd',
            'meta_value' => get_the_ID()
        ));
        if ( $pages_pgms ) {
            $page_link = get_permalink( $pages_pgms[0]->ID );
        }

    ?>
    <article <?php post_class( 'wp-course-post' ); ?>>
    <?php
    if ( isset( $page_link ) && amrwp_can_user_access_content(get_the_ID()) ) {
    ?>
    <a href="<?php echo $page_link; ?>">
    <?php
    }
    if ( has_post_thumbnail() ) {
        the_post_thumbnail( 'full' );
    }
    ?>
    <div class="wp-course-info">
        <h2 class="wp-post-title"><?php the_title(); ?></h2>
        <div class="wp-post-excerpt">
            <?php echo $post->post_excerpt; ?>
        </div>
        <!-- /.wp-post-excerpt -->
    <?php
    if ( isset( $page_link ) && amrwp_can_user_access_content(get_the_ID()) ) {
    ?>
    </a>
    <?php
    }
    ?>
    </div>
    <!-- /.wp-course-info -->
    
    </article>
    <?php
    ?>
    <?php
    endwhile;
    ?>
</div>
<!-- /.wp-programas-acompanhamento -->
<?php
endif;
?>

<?php get_footer(); ?>