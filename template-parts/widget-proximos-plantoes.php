<div class="widget plantoes md:mt-[20px] md:py-[20px] md:px-[1.2vw] bg-white">
    <h3 class="typog-title-med"><?php esc_attr_e('Próximos plantões','amrwp'); ?></h3>
    <div class="mt-[10px] recados-plantoes-slider-wrapper plantoes-slider-wrapper">
        <button class="btn-arrow arrow-prev -mt-[10px] relative z-20">
            <svg version="1.1" id="Layer_7" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
                width="8px" height="14.002px" viewBox="0 0 8 14.002" style="enable-background:new 0 0 8 14.002;" xml:space="preserve">
            <path class="st4" d="M0.293,6.295c-0.391,0.391-0.391,1.025,0,1.415l5.999,5.999c0.391,0.391,1.025,0.391,1.415,0
                s0.391-1.025,0-1.415L2.414,7.001l5.29-5.293c0.391-0.391,0.391-1.025,0-1.415s-1.025-0.391-1.415,0L0.29,6.292L0.293,6.295z"/>
            </svg>
        </button>
        <div class="px-[12px] recados-plantoes-slider plantoes-slider z-10">
            <?php
            $plnt_count = 0;
            foreach ($pgm_plnt as $pgm_plnt_item) {
                $plnt_count++;
            ?>
            <div class="px-[6px] plantao-item">
                <?php if ( ! empty($pgm_plnt_item['pgm_plnt_dt']) ) { $pgm_plnt_item_hr = explode(' ',$pgm_plnt_item['pgm_plnt_dt']); ?>
                    <?php if ( 1 == $plnt_count && isset( $pgm_plnt_item['lnk_d_zm'] ) && '' != $pgm_plnt_item['lnk_d_zm'] ) { ?>
                        <a href="<?php echo $pgm_plnt_item['lnk_d_zm']; ?> " target="_blank">
                    <?php } ?>
                <p class="flex flex-col justify-center items-center rounded-[22px] py-[10px] px-[12px] capitalize date"><span class="text-[11px]"><?php echo $pgm_plnt_item_hr[0]; ?></span><span class="mxmd:text-[19px] md:text-[17px]"><?php echo $pgm_plnt_item_hr[1]; ?></span><span class="text-[11px]"><?php echo $pgm_plnt_item_hr[2]; ?></span></p>
                <?php } ?>
                <?php if ( ! empty($pgm_plnt_item['pgm_plnt_hr']) ) { ?>
                <p class="mt-[4px] text-center text-[14px]"><?php echo $pgm_plnt_item['pgm_plnt_hr']; ?></p>
                <?php } ?>
                <?php if ( 1 == $plnt_count && isset( $pgm_plnt_item['lnk_d_zm'] ) && '' != $pgm_plnt_item['lnk_d_zm'] ) { ?>
                    </a>
                <?php } ?>
            </div>
            <?php
            }
            ?>
        </div>
        <button class="btn-arrow arrow-next -mt-[10px] relative z-20">
            <svg version="1.1" id="Layer_7" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" x="0px" y="0px"
                width="8px" height="14.002px" viewBox="0 0 8 14.002" style="enable-background:new 0 0 8 14.002;" xml:space="preserve">
            <path class="st4" d="M0.293,6.295c-0.391,0.391-0.391,1.025,0,1.415l5.999,5.999c0.391,0.391,1.025,0.391,1.415,0
                s0.391-1.025,0-1.415L2.414,7.001l5.29-5.293c0.391-0.391,0.391-1.025,0-1.415s-1.025-0.391-1.415,0L0.29,6.292L0.293,6.295z"/>
            </svg>
        </button>
    </div>
</div>