<article class="lp-dsm-reasons-item">
    <?php if ( '' != $motivo_icone ) { amrwp_img_tag_generate( $motivo_icone ); } ?>
    <?php if ( '' != $motivo_titulo ) { ?>
        <h3 class="lp-dsm-reasons-item-title"><?php echo $motivo_titulo; ?></h3>
    <?php } ?>
    <?php if ( '' != $motivo_texto ) { ?>
        <div class="lp-dsm-reasons-item-text"><?php echo $motivo_texto; ?></div>
    <?php } ?>
</article>