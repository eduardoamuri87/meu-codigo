<?php if ( class_exists('Sensei_Course_Structure') ) {
    $class_Sensei_Course_Structure = Sensei_Course_Structure::instance( $course_id );
    $course_structure = $class_Sensei_Course_Structure->get('view',true);
    
    $first_incomplete_lesson_id = $class_Sensei_Course_Structure->get_first_incomplete_lesson_id();

    $module_count = 0;
    foreach ($course_structure as $item) {
        $module_count++;
        $lessons_completed = 0;
        if ( !empty ( $item['type'] ) && 'module' == $item['type'] ) {
            ?>
            <ul class="pb-[22px] border-white [&:not(:last-child)]:border-b-1 [&:not(:first-child)]:mt-[20px] course-module"> 
                <li class="relative">
                <?php if ( ! empty( $item['title'] ) ) { ?>
                    <h2 class="relative z-10 [&:not(:only-child)]:mb-[18px] module-title">
                        <button class="w-full flex text-left leading-[1.1em] uppercase mxmd:text-[20px] typog-body-med btn-toggle-lessons-list module-name"><span data-module-text="<?php esc_attr_e('Módulo','amrwp'); ?>" class="module-count"><?php echo $module_count; ?></span><span class="module-name"><span class="module-name-sep">&nbsp;-&nbsp;</span><?php echo $item['title']; ?></span> <span class="icon-toggle ml-auto w-[89px] md:w-[119px] pl-[60px] md:pl-[100px]"><img src="<?php echo public_url(); ?>images/arrow-toggle.svg" width="19" height="19" class="arrow-toggle" alt=""></span></button>
                    </h2>
                <?php } ?>
            <?php
            if ( ! empty( $item['lessons'] ) ) {
            ?>
                    <div class="lessons-list">
                        <div class="lessons-list-scroll">
                            <ul>
            <?php
            foreach ( $item['lessons'] as $lesson) {
            ?>
                <?php if ( ! empty( $lesson['title'] ) && ! empty( $lesson['id'] ) ) { ?>
                    <?php
                    $lesson_status = 'not-watched';
                    if ( class_exists('Sensei_Utils') ) {
                        $user_completed_lesson = (new Sensei_Utils)->user_completed_lesson($lesson['id']);
                    }
                    ?>
                                <li <?php if ( is_singular( 'lesson' ) && isset($pageID) && $lesson['id'] == $pageID ) { ?>data-is-current-lesson<?php } ?> data-lesson-id="<?php echo $lesson['id']; ?>" class="relative bg-white [&:not(:first-child)]:mt-[8px]" data-lesson-id="<?php echo $lesson['id']; ?>">
                                    <h2>
                                        <a class="mxmd:text-[17px] mxmd:leading-[1.29em] py-[12px] pl-[10px] pr-[15px] flex w-full items-start lesson-link" href="<?php the_permalink( $lesson['id'] ); ?>">
                            <?php
                            if ( $user_completed_lesson ) {
                                $lessons_completed++;
                                $lesson_status = 'completed';
                            ?>
                            <img class="mr-[13px] mt-[2px]" src="<?php echo public_url(); ?>images/icon_check.svg" width="20" height="20" alt="">
                            <?php
                            }
                            if ( isset($first_incomplete_lesson_id) && $first_incomplete_lesson_id == $lesson['id'] ) {
                                $lesson_status = 'in-progress';
                            ?>
                            <img class="next-lesson mr-[13px] mt-[2px]" src="<?php echo public_url(); ?>images/icon_progress.svg" width="20" height="20" alt="">
                            <?php
                            }
                            if ( 'not-watched' == $lesson_status ) {
                            ?>
                            <img class="mr-[13px] mt-[2px]" src="<?php echo public_url(); ?>images/icon_play.svg" width="20" height="20" alt="">
                            <?php
                            }
                            ?>
                            <?php echo $lesson['title']; ?>
                            <?php

                            if ( function_exists('get_field') && get_field('lssn_dur',$lesson['id']) ) {
                                $lssn_dur = get_field('lssn_dur',$lesson['id']);
                                $lssn_tm_mnt = isset($lssn_dur['lssn_tm_mnt']) ? $lssn_dur['lssn_tm_mnt'] : '0';
                                $lssn_tm_scd = isset($lssn_dur['lssn_tm_scd']) ? $lssn_dur['lssn_tm_scd'] : '0';
                                if ( $lssn_tm_scd != '00' && $lssn_tm_scd != '0' && $lssn_tm_scd < 10 ) { $lssn_tm_scd = '0' . $lssn_tm_scd; }
                                    if ( ! empty ($lssn_tm_mnt) && ! empty($lssn_tm_scd) && $lssn_tm_mnt != 0 && $lssn_tm_scd != 0 ) {
                                ?><span class="mxmd:text-[14px] ml-auto pl-[20px] duration"><?php echo $lssn_tm_mnt . ':' . $lssn_tm_scd; ?></span><?php
                                }
                            }
                            ?>
                                        </a>
                                    </h2>
                                </li>
                <?php } ?>
            <?php
            } // foreach ( $item['lessons'] as $lesson) {
            ?>
                            </ul>
                        </div>
                    </div>
                    <span class="lessons-completed mxmd:text-[20px] typog-body-med absolute right-[35px] -top-[4px] z-1">
                        <?php if ( ! empty( $item['lessons'] ) ) { echo $lessons_completed . '/' . count($item['lessons']); } ?> 
                    </span>
                
                </li>
            <?php
            } // if ( ! empty( $item['lessons'] ) ) {
            ?>
            </ul>
            <?php

        } // if ( !empty ( $item['type'] ) && 'module' == $item['type'] ) {
        
    }
    
} ?>