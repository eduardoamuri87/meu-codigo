<?php
/**
 * Template name: Fale Comigo
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

include_once( 'includes/user-can-access.php' );

global $post;
$pageID = $post->ID;

if ( function_exists('get_field') ) {
    
    if ( get_field('flcmg_msg_wlcm', $pageID) ) {
        $flcmg_msg_wlcm = get_field('flcmg_msg_wlcm', $pageID);
    }
    if ( get_field('flcmg_msg_wlcm_img', $pageID) ) {
        $flcmg_msg_wlcm_img = get_field('flcmg_msg_wlcm_img', $pageID);
    }
    if ( get_field('flcmg_msg_wlcm_img_mobile', $pageID) ) {
        $flcmg_msg_wlcm_img_mobile = get_field('flcmg_msg_wlcm_img_mobile', $pageID);
    }

    if ( get_field('lnk_mlhr_xprnc',$pageID) ) {
        $lnk_mlhr_xprnc = get_field('lnk_mlhr_xprnc',$pageID);
    }
    
    $course_id = amrpw_get_program_course_id();
    if ( ! empty($course_id) && get_field('pgm_cor',$course_id) ) {
        $pgm_cor = get_field('pgm_cor',$course_id);
    }

    if ( get_field('cntt_eml','option') ) {
        $cntt_eml = get_field('cntt_eml','option');
    }

    if ( get_field('cntt_hrr','option') ) {
        $cntt_hrr = get_field('cntt_hrr','option');
    }
    
    if ( get_field('cntt_rds','option') ) {
        $cntt_rds = get_field('cntt_rds','option');
    }

    if ( get_field('cntt_tlfn','option') ) {
        $cntt_tlfn = get_field('cntt_tlfn','option');
        $cntt_tlfn_wa = preg_replace('/\s+/', '', $cntt_tlfn);
        $cntt_tlfn_wa = str_replace('-', '', $cntt_tlfn_wa);
        $cntt_tlfn_wa = str_replace('(', '', $cntt_tlfn_wa);
        $cntt_tlfn_wa = str_replace(')', '', $cntt_tlfn_wa);
    }

}

get_header('curso');
?>

<div class="mxmd:w-full mxxl:px-[1.6vw] px-[3.29vw] mxmd:flex-col flex md:flex-1 page-content-wrapper">

    <div class="md:pb-[40px] flex-1 page-content-container">
        <div class="mxxl:pt-[20px] pt-[3.29vw] relative page-content-welcome mxmd:overflow-hidden">
            <?php if ( isset($flcmg_msg_wlcm_img) ) { ?>
            <?php amrwp_img_tag_generate($flcmg_msg_wlcm_img, 'full', 'mxmd:hidden page-content-welcome-image mxmd:w-[36.66vw] md:w-[clamp(150px,15.37vw,275px)] md:max-w-[210px] md:h-auto md:ml-auto absolute md:bottom-[18px] md:right-[1.68vw] z-[10]', false); ?>
            <?php } ?>
            <?php if ( isset($flcmg_msg_wlcm_img_mobile) ) { ?>
            <?php amrwp_img_tag_generate($flcmg_msg_wlcm_img_mobile, 'full', 'md:hidden page-content-welcome-image mxmd:w-auto mxmd:max-w-none mxmd:h-[90%] absolute mxmd:top-[4%] mxmd:translate-x-[20%] mxmd:right-0 z-[10]', false); ?>
            <?php } ?>
            <div class="page-content-welcome-text md:py-[40px] md:pl-[2.19vw] md:pr-[25.5vw] relative z-[1]" <?php if ( ! empty($pgm_cor) ) { echo 'style="background-color:' . $pgm_cor . '"'; } ?>>
                <h1 class="leading-[1em] typog-title"><?php esc_attr_e('Fale comigo','amrwp'); ?></h1>
                <?php if ( isset($flcmg_msg_wlcm) ) { ?>
                <p class="mt-[15px] typog-body-small"><?php echo $flcmg_msg_wlcm; ?></p>
                <?php } ?>
            </div>
        </div>
        <!-- /.page-content-welcome -->
        <div class="mxmd:mt-[3.33vh] mxmd:px-[5vw] md:mt-[30px]">
            <ul class="content-tab link-tabs flex tabs gap-x-[2.92vw]">
                <li class="tab">
                    <a><?php esc_attr_e('Envie sua mensagem','amrwp'); ?></a>
                </li>
                <?php if ( isset($lnk_mlhr_xprnc) ) { ?>
                <li class="tab inactive mxmd:hidden">
                    <a target="_blank" href="<?php echo $lnk_mlhr_xprnc; ?>">Melhore sua experiência</a>
                </li>
                <?php } ?>
            </ul>
            <!-- /.content-tab -->
            <div class="mt-[30px] editor-content">
                <?php
                while ( have_posts() ): the_post();
                    the_content();
                endwhile;
                ?>
            </div>
        </div>
        <?php if ( isset($lnk_mlhr_xprnc) ) { ?>
        <div class="mxmd:mt-[30px] mxmd:px-[5vw]">
            <a class="md:hidden block border-b-[2px] border-solid border-blue-dark" target="_blank" href="<?php echo $lnk_mlhr_xprnc; ?>">Melhore sua experiência</a>
        </div>
        <?php } ?>
    </div>
    <!-- /.page-content -->

    <div class="ml-auto pl-[2.8vw] md:w-[26.6vw] md:min-w-[200px] pt-[3.29vw] mxxl:pl-[1.45vw] mxmd:pb-[30px] page-sidebar">
        
        <?php if ( isset($cntt_eml) || isset($cntt_tlfn) ) { ?>
        <div class="widget plantoes md:py-[25px] md:px-[2.19vw] bg-white">
            <h3 class="typog-title-med"><?php esc_attr_e('Contatos','amrwp'); ?></h3>
            <div class="mt-[10px]">
                <?php if ( isset($cntt_eml) ) { ?>
                    <p><a target="_blank" class="flex gap-x-[8px]" href="mailto:<?php echo $cntt_eml; ?>"><img src="<?php echo public_url(); ?>images/icone-contato_email.svg" width="16" height="12" alt=""> <span>eduardo@amuri.com.br</span></a></p>
                <?php } ?>
                <?php /**if ( isset($cntt_tlfn) ) { ?>
                    <p class="mt-[10px]"><a target="_blank" class="flex gap-x-[8px]" href="https://wa.me/55<?php echo $cntt_tlfn_wa; ?>"><img src="<?php echo public_url(); ?>images/icone-contato_whatsapp.svg" width="16" height="16" alt=""> <span><?php echo $cntt_tlfn; ?></span></a></p>
                <?php }*/?>
            </div>
            
        </div>
        <?php } ?>
        
        <?php /**if ( isset($cntt_hrr) ) { ?>
        <div class="widget plantoes md:py-[25px] md:px-[2.19vw] bg-white mt-[30px]">
            <h3 class="typog-title-med"><?php esc_attr_e('Horário de atendimento','amrwp'); ?></h3>
            <div class="mt-[10px]">
                <div class="flex items-start gap-x-[8px]"><img class="mt-[5px]" src="<?php echo public_url(); ?>images/icone-contato_horario.svg" width="14" height="14" alt=""> <span><?php echo $cntt_hrr; ?></span></div>
            </div>
            
        </div>
        <?php } */?>
        
        <?php if ( isset($cntt_rds) && ! empty($cntt_rds) ) { ?>
        <div class="widget plantoes md:py-[25px] md:px-[2.19vw] bg-white mt-[30px]">
            <h3 class="typog-title-med"><?php esc_attr_e('Minhas redes','amrwp'); ?></h3>
            <div class="mt-[10px] flex items-start gap-x-[15px]">
                <?php
                foreach ($cntt_rds as $rede) {
                ?>
                    <?php
                    if ( isset($rede['cntt_rds_lnk']) && isset($rede['cntt_rds_lnk']['title']) && isset($rede['cntt_rds_lnk']['url']) ) {
                    ?>
                    <a class="flex justify-center items-center rounded-[50%] bg-orange-light w-[33px] h-[33px]" title="<?php echo $rede['cntt_rds_lnk']['title']; ?>" <?php if ( isset($rede['cntt_rds_lnk']['target']) && '' != $rede['cntt_rds_lnk']['target'] ) { echo 'target="' . $rede['cntt_rds_lnk']['target'] . '"'; } ?> href="<?php echo $rede['cntt_rds_lnk']['url']; ?>">
                    <?php
                    }
                    if ( isset($rede['cntt_rds_img']) ) {
                        amrwp_img_tag_generate($rede['cntt_rds_img'],'full');
                    }
                    if ( isset($rede['cntt_rds_lnk']) ) { ?>
                    </a>
                    <?php } ?>
                <?php } ?>
            </div>
            
        </div>
        <?php } ?>

    </div>
    <!-- /.page-sidebar -->

</div>
<!-- /.page-content -->

<?php get_footer(); ?>