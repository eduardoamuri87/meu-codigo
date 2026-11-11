<article <?php post_class('cell'); ?>>
    <?php
    if ( 'amr_plantao_duvida' == $plnt_post_type && function_exists('get_field') && get_field('dvd_plnto',get_the_ID()) ) {
        $permalink = get_the_permalink( get_field('dvd_plnto',get_the_ID()) );
        if ( get_field('dvd_plnt_mntgm',get_the_ID()) ) {
            $dvd_plnt_mntgm = get_field('dvd_plnt_mntgm',get_the_ID());
            if ( $dvd_plnt_mntgm['dvd_plnt_mntgm_hr'] && $dvd_plnt_mntgm['dvd_plnt_mntgm_hr'] != 0 ) {
                $permalink .= '?vt=' . $dvd_plnt_mntgm['dvd_plnt_mntgm_hr']  . 'h';

                if ( $dvd_plnt_mntgm['dvd_plnt_mntgm_mnt'] && $dvd_plnt_mntgm['dvd_plnt_mntgm_mnt'] != 0 ) {
                    $permalink .= $dvd_plnt_mntgm['dvd_plnt_mntgm_mnt']  . 'm';

                    if ( $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd'] && $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd'] != 0 ) {
                        $permalink .= $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd']  . 's';
                    }

                } else {

                    if ( $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd'] && $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd'] != 0 ) {
                        $permalink .= $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd']  . 's';
                    }

                }

            }
            if ( ! $dvd_plnt_mntgm['dvd_plnt_mntgm_hr'] || ! isset ($dvd_plnt_mntgm['dvd_plnt_mntgm_hr']) || $dvd_plnt_mntgm['dvd_plnt_mntgm_hr'] == 0 ) {
                
                if ( $dvd_plnt_mntgm['dvd_plnt_mntgm_mnt'] && $dvd_plnt_mntgm['dvd_plnt_mntgm_mnt'] != 0 ) {
                    $permalink .= '?vt=' . $dvd_plnt_mntgm['dvd_plnt_mntgm_mnt']  . 'm';

                    if ( $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd'] && $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd'] != 0 ) {
                        $permalink .= $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd']  . 's';
                    }

                }

                else {

                    if ( $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd'] && $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd'] != 0 ) {
                        $permalink .= '?vt=' . $dvd_plnt_mntgm['dvd_plnt_mntgm_sgnd']  . 's';
                    }
    
                }

            } 
            
        }
    } else {
        $permalink = get_the_permalink();
    }
    ?>
    <h2>
        <a title="<?php echo get_the_title(); ?>" href="<?php echo $permalink; ?>">
            <span class="text">
                <span class="label">Plantão</span>
                <span class="title"><?php echo get_the_title(); ?></span>
            </span>
        </a>
    </h2>
</article>