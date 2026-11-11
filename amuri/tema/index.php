<?php
/**
 * The main template file
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

get_header();

?>

<?php
if ( have_posts() ): 
    while ( have_posts() ): the_post();
    ?>
    <article <?php post_class(); ?>>
    <?php
        the_content();
    ?>
    </article>
    <?php
    endwhile;
endif;
?>


<?php get_footer(); ?>