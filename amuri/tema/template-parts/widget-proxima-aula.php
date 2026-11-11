<div class="widget aula w-full md:py-[35px] md:px-[2.56vw] bg-white">
    <?php 
    if ( class_exists('Sensei_Course_Structure') ) {
        $class_Sensei_Course_Structure = Sensei_Course_Structure::instance( $course_id );
        $first_incomplete_lesson_id = $class_Sensei_Course_Structure->get_first_incomplete_lesson_id();
        if ( $first_incomplete_lesson_id ) {
        ?>
        <a href="<?php the_permalink( $first_incomplete_lesson_id ); ?>" class="btn-primary btn-arrow-link"><?php esc_attr_e('Começar próxima aula','amrwp'); ?></a>
        <p class="mt-[25px] truncate"><?php echo get_the_title( $first_incomplete_lesson_id ); ?></p>
        <?php
        }
    }
    ?>
</div>