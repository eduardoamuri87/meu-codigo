<?php
/**
 * The template for displaying the footer
 *
 * Contains the closing of the #content div and all content after
 *
 * @package WordPress
 * @subpackage Amuri Plataforma
 * @since Amuri Plataforma 1.0
 */
?>

    <footer>
        
    </footer>
    <!-- /.site-footer -->

</div>
<!-- /#page -->

<style>
    @font-face {
    font-family: "Vinila Condensed";
    src:
        url("<?php echo public_url(); ?>fonts/Vinila-CondensedLight.otf") format("opentype"),
        url("<?php echo public_url(); ?>fonts/Vinila-CondensedLight.woff") format("woff"),
        url("<?php echo public_url(); ?>fonts/Vinila-CondensedLight.woff2") format("woff2");
    }
    @font-face {
        font-family: 'Helvetica Neue Condensed Black';
        src: url("<?php echo public_url(); ?>fonts/HelveticaNeueLTPro-BlkCn.otf") format("opentype");
    }
</style>

<?php wp_footer(); ?>

<div class="page-overlay toggle-user-menu block w-screen h-screen fixed top-0 left-0 z-800 bg-black"></div>
<?php include_once('includes/user-menu.php'); ?>
</body>
</html>
