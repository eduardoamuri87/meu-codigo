<?php
/**
 * Amuri Plataforma functions and definitions.
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */

/**
 * Configurações iniciais do tema
 */
require get_template_directory() . '/includes/theme-configuration.php';

/**
 * Funções do tema
 */
require get_template_directory() . '/includes/theme-functions.php';

/**
 * Custom post types e custom taxonomies
 */
require get_template_directory() . '/includes/custom-types.php';

/**
 * Campos ACF registrados pelo código (complementam os grupos do banco)
 */
require get_template_directory() . '/includes/acf-campos-extras.php';
