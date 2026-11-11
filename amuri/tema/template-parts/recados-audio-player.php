<article class="px-[12px] recado-post-item">
    <?php if ( ! empty( $pgm_recd['pgm_rec_dt'] ) ) { ?>
        <p class="text-[12px]"><?php echo $pgm_recd['pgm_rec_dt']; ?></p>
    <?php } ?>
    <?php if ( ! empty( $pgm_recd['pgm_rec_tit'] ) ) { ?>
        <h3 class="font-sans-black text-[14px]"><?php echo $pgm_recd['pgm_rec_tit']; ?></h3>
    <?php } ?>
    <?php if ( ! empty( $pgm_recd['pgm_rec_txt'] ) ) { ?>
        <div class="mt-[7px] text-[15px] leading-[1.2em]"><?php echo $pgm_recd['pgm_rec_txt']; ?></div>
    <?php } ?>
    <?php if ( ! empty( $pgm_recd['pgm_rec_fl'] ) && 'audio' == $pgm_recd['pgm_rec_fl']['type'] ) { ?>
    <div class="mt-[7px] recados-player-container">
        <audio preload="auto" controls>
            <source src="<?php echo $pgm_recd['pgm_rec_fl']['url']; ?>">
        </audio>
    </div>
    <?php } ?>
</article>