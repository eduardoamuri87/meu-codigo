<?php
/**
 * Template para os posts de Plantoes
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

include_once( 'includes/user-can-access.php' );

global $post;
$postID = $post->ID;

if ( function_exists('get_field') ) {

    if ( get_field('plnt_vdo', $postID) ) {
        $plnt_vdo = get_field('plnt_vdo', $postID);
    }
    if ( get_field('plnt_vdo_url', $postID) ) {
        $plnt_vdo_url = get_field('plnt_vdo_url', $postID);
    }
    if ( get_field('plnt_vdo_url_embed', $postID) ) {
        $plnt_vdo_url_embed = get_field('plnt_vdo_url_embed', $postID);
    }

    if ( get_field('plnt_mntgm', $postID) ) {
        $plnt_mntgm = get_field('plnt_mntgm', $postID);
    }
    
}

get_header('curso');

while ( have_posts() ): the_post();
?>

    <div class="mxmd:w-full mxxl:px-[1.6vw] pl-[3.29vw] pr-[3.29vw] mxmd:flex-col mxmd:flex flex-1 page-content-wrapper">
        <div class="mxmd:pb-[3.33vh] pb-[30px] page-plantao-content page-content-container">

            <div class="single-content-infos">
                <h1 class="typog-title-g"><?php esc_attr_e('Plantão do dia','amrwp'); ?> <?php the_title(); ?></h1>
                
                <?php
                if ( ! empty($plnt_vdo_url) && wp_oembed_get($plnt_vdo_url) ) {
                    $wp_oembed_get = wp_oembed_get($plnt_vdo_url);
                    if ( isset($_REQUEST['vt']) && $_REQUEST['vt'] ) {

                        $iframe_doc = new DOMDocument();
                        $iframe_doc->loadHTML($wp_oembed_get);
                        $video_src = $iframe_doc->getElementsByTagName('iframe')->item(0)->getAttribute('src');
                        
                        if ( str_contains( $video_src, '?' ) ) {
                            $video_src_arr = explode('?',$video_src);
                            $video_src_w_time = $video_src_arr[0] . '#t=' . $_REQUEST['vt'] . '?' . str_replace('&','&amp;',$video_src_arr[1]);
                        } else {
                            $video_src_w_time = $video_src . '#t=' . $_REQUEST['vt'];
                        }

                        $wp_oembed_get = str_replace(str_replace('&','&amp;',$video_src),$video_src_w_time,$wp_oembed_get);

                    }

                ?>
                <div class="mt-[20px]">
                    <?php if ( isset($plnt_vdo_url_embed) ) { ?>
                    <div class="vimeo-video-wrapper">
                        <?php echo $plnt_vdo_url_embed; ?>
                    </div>
                    <!-- /.vimeo-video-wrapper -->
                     <?php } ?>
                </div>
                <?php
                }
                
                
                $post_assuntos = wp_get_post_terms($postID, 'amr_plantao_assunto');
                if ( $post_assuntos ) {
                ?>
                <div class="plantao-terms py-[12px] flex items-center gap-x-[12px] text-[14px]">
                    <span class="mr-[12px]">Assuntos:</span> <?php foreach ($post_assuntos as $assunto) {?> <a href="<?php echo get_permalink(345); ?>?assunto=<?php echo $assunto->slug; ?>" class="btn-secondary"><?php echo $assunto->name; ?></a> <?php
                    } ?>
                </div>
                <!-- /.plantao-terms -->
                <?php
                }

                if ( isset ($plnt_mntgm) ) {
                ?>
                <div class="mt-[20px] plantao-minutagem">
                    <p class="label pb-[30px]"><span class="inline-block border-b-[2px] border-blue-dark">Minutagem</span></p>
                </div>
                <!-- /.plantao-minutagem -->
                <?php
                }
                ?>
        </div>
        <!-- /.single-content-infos -->

        <?php 
        if ( isset ($plnt_mntgm) ) {
        ?>

            <div class="minutagem-custom-scroll">
                <?php
                foreach ($plnt_mntgm as $minutagem) {
                    if ( isset($minutagem['plnt_mntgm_tmp']) && isset($minutagem['plnt_mntgm_txt']) ) {
                    ?>
                    <div class="pb-[30px]">
                        <p><?php echo $minutagem['plnt_mntgm_tmp']; ?></p>
                        <p><?php echo $minutagem['plnt_mntgm_txt']; ?></p>
                    </div>
                    <?php
                    }
                }
                ?>
            </div>
        <?php
        }
        ?>


    </div>
    <!-- /.page-content-container -->

</div>
<!-- /.page-content -->

<?php
endwhile; // while ( have_posts() ): the_post();
get_footer();
?>