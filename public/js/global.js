/*
 * Funções globais
 */

(function($) {

    $.fn.focusTextToEnd = function(){
        this.focus();
        var $thisVal = this.val();
        this.val('').val($thisVal);
        return this;
    }

    const isValidUrl = function(string_url) {
        try {
          new URL(string_url);
          return true;
        } catch (err) {
          return false;
        }
    }

    // Eventos iniciais
    const init_events = function() {

        var amrwp_CheckWindowSizeTimer;
        function amrwp_CheckWindowSize() {
            document.documentElement.style.setProperty( '--site-body-h', window.innerHeight + 'px' );
            document.documentElement.style.setProperty( '--site-header-h', $('.curso-header-top').innerHeight() + 'px' );

            if ( document.querySelectorAll('.editor-text-expand').length ) {
                editor_text_expand();
            }

            if ( document.querySelectorAll('#plantaoFrom').length ) {
                move_plantao_date_picker();
            }
   
        }

        window.onresize = function() {
            clearTimeout(amrwp_CheckWindowSizeTimer);
            amrwp_CheckWindowSizeTimer = setTimeout(amrwp_CheckWindowSize, 250);
        }
        amrwp_CheckWindowSize();

        if ( document.querySelector('[data-placeholder-comment]') && document.querySelector('[data-placeholder-comment]').dataset.placeholderComment ) {

            document.querySelector('[data-placeholder-comment] textarea#comment').placeholder = document.querySelector('[data-placeholder-comment]').dataset.placeholderComment;
            document.querySelector('[data-placeholder-comment] textarea#comment').required = 'required';

        }

        if ( document.querySelector('#amrwp_login_form #user_login') ) {
            if ( amrwp_placeHolderForLoginForm.amrwp_LoginFormUsernamePlaceholder ) {
                document.querySelector('#amrwp_login_form #user_login').placeholder = amrwp_placeHolderForLoginForm.amrwp_LoginFormUsernamePlaceholder;
            }
            if ( amrwp_placeHolderForLoginForm.amrwp_LoginFormPasswordPlaceholder ) {
                document.querySelector('#amrwp_login_form #user_pass').placeholder = amrwp_placeHolderForLoginForm.amrwp_LoginFormPasswordPlaceholder;
            }
        }

        if ( document.querySelectorAll('.curso-menu-toggle').length ) {
            curso_toggle_menu();
        }

        if ( document.querySelectorAll('.btn-toggle-menu-mobile').length ) {
            curso_toggle_menu_mobile();
        }

        if ( document.querySelectorAll('.toggle-user-menu').length ) {
            toggle_user_menu();
        }

        if ( document.querySelectorAll('.editor-text-expand').length ) {
            editor_text_expand();
        }

        if ( document.querySelectorAll('.recados-player-container').length && 'function' === typeof jQuery().audioPlayer ) {
            $('audio').audioPlayer();
        }

        if ( document.querySelectorAll('.lp-dsm-testimonials-list .lp-dsm-testimonials-item').length > 1 && 'function' === typeof jQuery().slick ) {
            
            $('.lp-dsm-testimonials-list').slick({
                'dots': true,
                'mobileFirst': true,
                'draggable': true,
                'adaptiveHeight': true,
                'infinite': false,
                'prevArrow': '.lp-dsm-testimonials-list-arrow.arrow-prev',
                'nextArrow': '.lp-dsm-testimonials-list-arrow.arrow-next',
            });

        }

        if ( document.querySelectorAll('.recados-slider .recado-post-item').length > 1 && 'function' === typeof jQuery().slick ) {
            
            $('.recados-slider').slick({
                'dots': true,
                'mobileFirst': true,
                'draggable': false,
                'infinite': false,
                'prevArrow': '.recados-slider-wrapper .btn-arrow.arrow-prev',
                'nextArrow': '.recados-slider-wrapper .btn-arrow.arrow-next',
            });

        }

        if ( document.querySelectorAll('.plantoes-slider > div').length > 1 && 'function' === typeof jQuery().slick ) {
            
            $('.plantoes-slider').slick({
                'slidesToShow': 4,
                'draggable': false,
                'mobileFirst': true,
                'infinite': false,
                'prevArrow': '.plantoes-slider-wrapper .btn-arrow.arrow-prev',
                'nextArrow': '.plantoes-slider-wrapper .btn-arrow.arrow-next',
                responsive: [
                    {
                        breakpoint: 1200,
                        settings: {
                            slidesToShow: 4
                        }
                    },
                    {
                        breakpoint: 990,
                        settings: {
                            slidesToShow: 3
                        }
                    },
                    {
                        breakpoint: 768,
                        settings: {
                            slidesToShow: 3
                        }
                    },
                ]
            });

        }

        if ( document.querySelectorAll('.content-tabs-wrapper .tab a').length ) {
            init_content_tabs();
        }

        if ( document.querySelectorAll('.btn-toggle-lessons-list').length ) {
            toggle_lessons_list();
        }

        if ( document.querySelector('.lesson_button_form [type="submit"].quiz-submit.complete') ) {
            if ( amrwp_placeHolderForLoginForm.amrwp_FinishLessonGoToNextLessons ) {
                document.querySelector('.lesson_button_form [type="submit"].quiz-submit.complete').value = amrwp_placeHolderForLoginForm.amrwp_FinishLessonGoToNextLessons;
            }
        }

        if ( document.querySelectorAll('.page-nav-filter .tabs .btn-term').length ) {
            plantoes_show_more_terms();
        }
        
        if ( document.querySelectorAll('.page-nav-filter .tab-date').length ) {
            plantoes_init_date_picker();
        }

        if ( document.querySelectorAll('.page-nav-filter .filter-link.open-tab').length ) {
            plantoes_toggle_tab();
        }
        
        if ( document.querySelectorAll('.btn-show-more-plantoes').length ) {
            plantoes_load_more_click();
        }

        if ( document.querySelectorAll('.plantoes-grid .cell a').length ) {
            plantao_click_open();
        }
        
        if ( document.querySelectorAll('.form-edit-user-profile').length ) {
            form_edit_user_profile_events();
        }
        if ( document.querySelectorAll('.btn-toggle-panel').length ) {
            btn_toggle_panel();
        }

        if ( document.querySelectorAll('body.woocommerce-checkout') && document.querySelectorAll('body.woocommerce-checkout #customer_details') ) {
            change_checkout_form_tab_order();
        }

        if ( document.querySelectorAll('body.woocommerce-checkout').length && document.querySelectorAll('body.woocommerce-checkout #payment_method_iugu-credit-card').length ) {
            checkout_cc_installments_order();
        }

        if ( document.querySelectorAll('.open-my-programs').length ) {
            open_programs_button();
        }

        if ( document.querySelectorAll('.lp-faq-item').length ) {
            faq_toggle_lp_pgm();
        }

    }; // const init_events = function() {

    const faq_toggle_lp_pgm = function() {

        $('.lp-faq-item-title-btn').on('click', function () {
            
            $btn = $(this);
            $btn.toggleClass('active');
            $btn.parent().parent().toggleClass('active');
            $btn.parent().parent().find('.lp-faq-item-text').slideToggle();

        });

    };

    const open_programs_button = function() {
        window.amr_perfil_programs_should_open = false;

        if ( $('#menu-item-251').length && $('body.page-template-page-editar-perfil').length ) { $('#menu-item-251').addClass('open-my-programs'); }

        $('body').on('click', '.open-my-programs', function(evt) {
            evt.preventDefault();

            if ( $('body').hasClass('user-menu-open') ) {
                document.querySelector('html').classList.toggle('user-menu-open');
                document.querySelector('body').classList.toggle('user-menu-open');
                document.documentElement.style.setProperty( '--site-body-h', window.innerHeight + 'px' );
            }
            
            window.amr_perfil_programs_should_open = true;

            $('[name="editar-perfil"] ~ .toggle-panel').slideUp(function() {

                if ( window.amr_perfil_programs_should_open ) {
                    $('[name="meus-programas"] ~ .toggle-panel').slideDown(function() {

                        $('html, body').animate({
                            scrollTop: $('[name="meus-programas"] ~ .toggle-panel').offset().top - 200
                        }, 500);

                        window.amr_perfil_programs_should_open = false;

                    });

                }

            });
            
        });

    };

    const checkout_cc_installments_order = function() {
        window.payment_method_iugu_credit_card_checked = false;

        $('body').on('updated_checkout', change_checkout_cc_installments_order );

    }

    const change_checkout_cc_installments_order = function() {
        
        if ( $('#iugu-card-installments option').length < 3 ) return;

        if ( ! $('#payment_method_iugu-credit-card:checked').length && window.payment_method_iugu_credit_card_checked == true ) {
            window.payment_method_iugu_credit_card_checked = false;
            return;
        }

        if ( $('#payment_method_iugu-credit-card:checked').length && window.payment_method_iugu_credit_card_checked ) return;
    
        if ( $('#payment_method_iugu-credit-card:checked').length && window.payment_method_iugu_credit_card_checked == false ) {
            window.payment_method_iugu_credit_card_checked = true;
            
            var $select = $('#iugu-card-installments');
            var option_first = $select.find('option:first-child');
            var options = $select.find('option:not(:first-child');

            options = [].slice.call(options).reverse();

            $select.empty();
            $select.append($(option_first));

            $.each(options, function (i, el) {
                $select.append($(el));
            });

        }

    };

    const change_checkout_form_tab_order = function() {

        if ( $('#wpadminbar .screen-reader-shortcut').length ) {
            $('#wpadminbar .screen-reader-shortcut').attr("tabindex", 100);
        }

        if ( $('#billing_first_name').length ) {
            $('#billing_first_name').attr("tabindex", 1);
        }
        if ( $('#billing_last_name').length ) {
            $('#billing_last_name').attr("tabindex", 2);
        }
        if ( $('#billing_cpf').length ) {
            $('#billing_cpf').attr("tabindex", 3);
        }
        if ( $('#billing_phone').length ) {
            $('#billing_phone').attr("tabindex", 4);
        }
        if ( $('#billing_email').length ) {
            $('#billing_email').attr("tabindex", 5);
        }
        
        if ( $('#billing_country').length ) {
            $('#billing_country').attr("tabindex", 6);
        }
        if ( $('#billing_postcode').length ) {
            $('#billing_postcode').attr("tabindex", 7);
        }
        if ( $('#billing_address_1').length ) {
            $('#billing_address_1').attr("tabindex", 8);
        }
        if ( $('#billing_number').length ) {
            $('#billing_number').attr("tabindex", 9);
        }
        if ( $('#billing_address_2').length ) {
            setTimeout(function() {
                $('label[for="billing_address_2"]').attr('class','');
            }, 100);
            
            $('#billing_address_2').attr("tabindex", 10);
        }
        if ( $('#billing_neighborhood').length ) {
            $('#billing_neighborhood').attr("tabindex", 11);
        }
        if ( $('#billing_city').length ) {
            $('#billing_city').attr("tabindex", 12);
        }
        if ( $('#billing_state').length ) {
            $('#billing_state').attr("tabindex", 13);
        }

    }

    const btn_toggle_panel = function() {

        $('.btn-toggle-panel').each(function(){

            $(this).on('click', function() {

                $(this).toggleClass('active').next().slideToggle();

            });

        });

    };

    const form_profile_search_cep = function() {

        let $field = $('#entregacep'),
            field_val = $field.val();
        if ( field_val == '' || field_val.replace(/\s+/g, '') == '' || field_val.length < 9 ) {
            $field.parent().addClass('field-error');
            $field.parents('form').find('[type="submit"]').attr('disabled','disabled');
            return false;
        }
        if ( /^[0-9]{5}-[0-9]{3}$/.test(field_val) ) {
            $field.parent().removeClass('field-error');
        }

        $field.attr('readonly','readonly');
        $field.parents('form').addClass('loading');
        $field.parents('form').find('[type="submit"]').attr('disabled','disabled');

        $.ajax({
            url: "https://viacep.com.br/ws/"+ field_val.replace('-','') +"/json/",
            type: "GET",
            dataType: "json",
            success: function (data) {

                if(data.erro !== undefined){
                    $field.parent().addClass('field-error');
                    $field.parents('form').find('[type="submit"]').attr('disabled','disabled');
                }else{
                    $("#entregalogradouro").val(data.logradouro);
                    $("#entregacidade").val(data.localidade).parent().removeClass('field-error');
                    $("#entregaestado").val(data.uf).parent().removeClass('field-error');
                    $field.parents('form').find('[type="submit"]').removeAttr('disabled');
                }
                
            },
            error: function(data){
                alert("CEP não encontrado, desculpe, verifique o número digitado.");
            },
            complete: function(){
                $field.removeAttr('readonly');
                $field.parents('form').removeClass('loading');
            }
        });

    };

    const form_edit_user_profile_events = function() {

        $('#entregacep').mask("99999-999").on('blur', form_profile_search_cep);

        $('.form-edit-user-shipping').on('submit', function(evt) {
            evt.preventDefault();
            let $form = $(this),
                $field = $('#entregacep'),
                field_val = $field.val();

            if ( field_val == '' || field_val.replace(/\s+/g, '') == '' || field_val.length < 9 ) {
                $field.parent().addClass('field-error');
                $field.parents('form').find('[type="submit"]').attr('disabled','disabled');
                alert('O CEP digitado é inválido. Verifique e tente novamente antes de atualizar as informações de faturamento.');
                return false;
            }
            if ( /^[0-9]{5}-[0-9]{3}$/.test(field_val) ) {
                $field.parent().removeClass('field-error');
            }

            $('#entregacep').attr('readonly','readonly');
            $form.addClass('loading');
            $form.find('[type="submit"]').attr('disabled','disabled');

            $form.find('.form-msg').hide();

            $.ajax({
                url: amrwp_Ajax.amrwp_AjaxURL,
                type: "POST",
                data: new FormData(this),
                contentType: false,
                cache: false,
                processData:false,
                success: function(data)
                {

                    $form.removeClass('loading');

                    if ( data.indexOf('Erropadrao-') > -1 ) {
                        
                        $form.find('.form-all-error-msg').show().text( data.replace('Erropadrao-','') );
                        
                    }
                    if ( data.indexOf('Errofields-') > -1 ) {

                        let fields_erro = data.replace('Errofields-','').split('-');
                        
                        fields_erro.forEach(field_error => {
                            
                            $('#entrega' + field_error).parent().addClass('field-error');

                        });
                        
                        $form.find('.form-all-error-msg').show().text( $form.find('.form-all-error-msg').data('invalidos') );

                    }
                    
                    if ( data.indexOf('Sucesso-') > -1 ) {
                        
                        $form.find('.form-row').removeClass('editing');
                        $form.find('.field-error').removeClass('field-error');

                        $form.find('.form-success-msg').text( $form.find('.form-success-msg').data('msg') ).show();
                        setTimeout( function() {
                            $form.find('.form-msg').hide();
                        }, 5000);
                        

                    }
                },
                complete: function(){
                    $('#entregacep').removeAttr('readonly');
                    $form.find('[type="submit"]').removeAttr('disabled');
                }   
            });

        });

        $('.btn-edit-profile-image, .btn-add-profile-image').on('click', function() {

            let $btn = $(this);
            $btn.parents('.form-row').addClass('editing');
            $btn.parents('.form-row').find('[name="perfilimagem"]').trigger('click');
            $('.form-edit-user-profile .form-msg').hide();

        });

        $('.btn-edit-field').on('click', function() {

            let $btn = $(this);
            $btn.parents('.form-row').data('old-value',$btn.parents('.form-row').find('.field-to-edit').val()).addClass('editing').find('.field-to-edit').removeAttr('disabled').focusTextToEnd();
            $('.form-edit-user-profile .form-msg').hide();

        });

        $('.btn-cancel-edit').on('click', function() {

            let $btn = $(this),
                field_old_value = $btn.parents('.form-row').data('old-value');
            $btn.parents('.form-row').removeClass('editing').find('.field-to-edit').attr('disabled', 'disabled');
            if ( field_old_value && field_old_value.trim().length !== 0 ) {
                $btn.parents('.form-row').find('.field-to-edit').val( field_old_value );
            }
            $('.form-edit-user-profile .form-msg').hide();

        });

        $('.form-add-profile-image').on('submit', function(evt) {
            evt.preventDefault();
            $form = $(this);

            if ( '' == $form.find('[name="perfilimagem"]').val() || ! $form.find('[name="perfilimagem"]').val() ) {
                alert('Escolha o arquivo da imagem antes de salvar.');
                return;
            }

            $form.find('.form-row').addClass('loading');
            $form.find('.form-msg').hide();

            $.ajax({
                url: amrwp_Ajax.amrwp_AjaxURL,
                type: "POST",
                data: new FormData(this),
                contentType: false,
                cache: false,
                processData:false,
                success: function(data)
                {

                    $form.find('.form-row').removeClass('loading');

                    if ( data.indexOf('Erro-') > -1 ) {
                        $form.find('.form-error-msg').show().text( data.replace('Erro-','') );
                    }
                    
                    if ( data.indexOf('Sucesso-') > -1 ) {
                        window.location = window.location.href.split('?')[0]+'?eraseCache=' + Math.floor(Math.random() * (9999999999999999 - 99999999 + 1) + 99999999);

                    }
                }	        
            });

        });

        $('.form-edit-user-profile').on('submit', function(evt) {
            evt.preventDefault();

            $form = $(this);
            let form_nonce = $form.data('nonce'),
                form_action = $form.data('action'),
                $form_field = $form.find('.field-to-edit'),
                form_field_name = $form_field.attr('name'),
                form_field_value = $form_field.val();

            if ( ! form_field_value || form_field_value.trim().length === 0 ) {
                return;
            }

            $form.find('.form-row').addClass('loading');
            $('.form-edit-user-profile .form-msg').hide();

            $.ajax({
                url: amrwp_Ajax.amrwp_AjaxURL,
                type : "post",
                dataType : "html",
                cache: false,
                data: {
                    'nonce' : form_nonce,
                    'action' : form_action,
                    'form_field_name' : form_field_name,
                    'form_field_value' : form_field_value
                },
                success: function(response) {

                    $form.find('.form-row').removeClass('editing loading').find('.field-to-edit').attr('disabled', 'disabled');

                    if ( response.indexOf('Erro-') > -1 ) {
                        
                        $form.find('.form-error-msg').show().text( response.replace('Erro-','') );
                        let field_old_value = $form.find('.form-row').data('old-value');
                        if ( field_old_value ) {
                            $form.find('.form-row .field-to-edit').val( field_old_value );
                        }

                    } else {

                        if ( response.indexOf('Sucesso-Senha') > -1 ) {

                            if(!alert( $('.form-password-change-msg').data('msg') )){
                                window.location = window.location.href.split('?')[0]+'?eraseCache=' + Math.floor(Math.random() * (9999999999999999 - 99999999 + 1) + 99999999);
                            }
                            return;

                        }

                        if ( response.indexOf('Sucesso-') > -1 ) {

                            $form.find('.form-success-msg').text( $form.find('.form-success-msg').data('msg') ).show();
                            setTimeout( function() {
                                $form.find('.form-success-msg').hide();
                            }, 5000);

                        }

                        if ( 'perfilnome' == form_field_name || 'perfilsobrenome' == form_field_name && $('.user-menu-first-last-names').length ) {
                            $('.user-menu-first-last-names').text( response );
                            $form.find('.form-success-msg').text( $form.find('.form-success-msg').data('msg') ).show();
                            setTimeout( function() {
                                $form.find('.form-success-msg').hide();
                            }, 5000);
                        }

                    }

                } // success: function(response) {
    
            }); // $.ajax({

        });

    };

    const plantao_click_open = function() {

        if ( window.innerWidth < 768 ) return;

        $('.single-content').on('click','.btn-close', function(evt) {

            $('body').removeClass('show-single-plantao');
            $('html,body').removeClass('hidescroll');
            $('.single-plantao-wrapper').removeClass('is-loading');

        });

        $('.single-plantao-wrapper').on('click','.overlay', function(evt) {

            $('body').removeClass('show-single-plantao');
            $('html,body').removeClass('hidescroll');
            $('.single-plantao-wrapper').removeClass('is-loading');

        });

        $('.plantoes-grid-posts').on('click','.cell a', function(evt) {
            evt.preventDefault();

            let $post = $(this);
            let post_href = $post.attr('href');

            if ( post_href ) {

                $('.single-plantao-wrapper .single-content .post-content').html('');

                $('body').addClass('show-single-plantao');
                $('html,body').addClass('hidescroll');
                $('.single-plantao-wrapper').addClass('is-loading');

                let post_total_h = $('.post-content').height();
                
                $.ajax({
                    url: post_href,
                    type : "get",
                    dataType : "html",
                    cache: false,
                    success: function(response) {
                        
                        let html_response = $.parseHTML(response);
                        let $single_plantao = $(html_response).find('.page-plantao-content');
                        $single_plantao.appendTo( '.single-plantao-wrapper .single-content .post-content' );

                        setTimeout(function() {

                            let post_infos_h = $('.single-content-infos').height();
                            $('.minutagem-custom-scroll').css('height', post_total_h - post_infos_h );
                            $('.minutagem-custom-scroll').mCustomScrollbar();
                        
                            $('.single-plantao-wrapper').removeClass('is-loading');

                        },250);
                        
                    }
                });

            }

        });

    };

    const plantoes_load_more_click = function() {

        $('.btn-show-more-plantoes').on('click', function(evt) {
            evt.preventDefault();
            load_more_plantoes();
        });

    };

    const load_more_plantoes = function() {
        
        let nextContent,
            post_type = '',
            term_programa = '',
            term_assunto = '',
            plantaoFrom = '',
            plantaoTo = '',
            $nextEl = $('.plantoes-pagination-wrapper .next').first(),
            pagenum = $nextEl.parent().find('.current + a.page-numbers').first().text(),
            nonce = $('.plantoes-grid').data('nonce'),
            action = $('.plantoes-grid').data('action');

        if ( $('.plantoes-grid-posts').data('term-programa') ) {
            term_programa = $('.plantoes-grid-posts').data('term-programa');
        }

        if ( $('.plantoes-grid-posts').data('term-assunto') ) {
            term_assunto = $('.plantoes-grid-posts').data('term-assunto');
        }

        if ( $('.plantoes-grid-posts').data('post-type') ) {
            post_type = $('.plantoes-grid-posts').data('post-type');
        }

        if ( $('#plantaoFrom').val() ) {
            plantaoFrom = $('#plantaoFrom').val();
        }

        if ( $('#plantaoTo').val() ) {
            plantaoTo = $('#plantaoTo').val();
        }


        if ( $nextEl.length && pagenum && action ) {

            $('.posts-load-more').addClass('is-loading');
            $.ajax({
                url: amrwp_Ajax.amrwp_AjaxURL,
                type : "post",
                dataType : "html",
                cache: false,
                data: {
                    'nonce' : nonce,
                    'action' : action,
                    'pagenum' : pagenum,
                    'plantaoFrom' : plantaoFrom,
                    'plantaoTo' : plantaoTo,
                    'post_type' : post_type,
                    'term_programa' : term_programa,
                    'term_assunto' : term_assunto
                },
                success: function(response) {

                    $('.posts-load-more').removeClass('is-loading');

                    nextContent = $( response );
                    
                    $('.plantoes-grid-posts .plantoes-pagination-wrapper').remove();
                    $('.plantoes-grid-posts .plantoes-grid').append( nextContent );

                    setTimeout(function() {
                        if ( ! $('.plantoes-grid-posts .plantoes-pagination-wrapper .next').length ) {
                            $('.btn-show-more-plantoes').slideUp('fast');
                        }
                    }, 250)

                } // success: function(response) {

            }); // $.ajax({

        } // if ( $nextEl.length && pagenum && action ) {

    } // const load_more_plantoes = function() {

    const plantoes_toggle_tab = function() {

        document.querySelectorAll('.page-nav-filter .filter-link.open-tab').forEach(btn => {
            
            btn.addEventListener('click', function(evt) {
                
                let datasetBtn = btn.dataset.tabbutton;

                if ( btn.classList.contains('active') ) {
                    btn.classList.remove('active');

                    if ( datasetBtn && document.querySelector('[data-tab-name="'+ datasetBtn +'"]') ) {
                        $('[data-tab-name="'+ datasetBtn +'"]').slideUp();
                    }
                    return;
                }

                if ( document.querySelector('.page-nav-filter .filter-link.open-tab.active') ) {
                    let btnActive = document.querySelector('.page-nav-filter .filter-link.open-tab.active');
                    let datasetBtnActive = btnActive.dataset.tabbutton; ;
                    btnActive.classList.remove('active');
                    if ( datasetBtnActive && document.querySelector('[data-tab-name="'+ datasetBtnActive +'"]') ) {
                        $('[data-tab-name="'+ datasetBtnActive +'"]').slideUp();
                    }

                }

                btn.classList.add('active');
                if ( datasetBtn && document.querySelector('[data-tab-name="'+ datasetBtn +'"]') ) {
                    $('[data-tab-name="'+ datasetBtn +'"]').slideDown();
                }

            });

        });

    };

    const move_plantao_date_picker = function() {
        if ( window.innerWidth > 767 ) {
            
            if ( !$('.page-nav-filter-first .tabs [data-tab-name="data"]').length ) {

                $('[data-tab-name="data"]').appendTo( '.page-nav-filter-first .tabs' );

            }

        } else {

            if ( !$('.page-nav-filter-third .tabs [data-tab-name="data"]').length ) {

                $('[data-tab-name="data"]').appendTo( '.page-nav-filter-third .tabs' );

            }

        }

    };

    const plantoes_init_date_picker = function() {

        $.datepicker.setDefaults(
            $.extend(
              {'dateFormat':'dd-mm-yy'},
              $.datepicker.regional['pt-BR']
            )
        );
        let minDate = "+1w";

        if ( document.querySelector('[data-plantao-first-date]') ) {
            minDate = document.querySelector('[data-plantao-first-date]').dataset.plantaoFirstDate;
        }

        let dateFormat = "dd/mm/yy",
            from = $( "#plantaoFrom" )
                .datepicker({
                defaultDate: "+1w",
                minDate: minDate,
                changeMonth: true,
                weekHeader: "W",
                maxDate: '+0m +0w',
                dateFormat: dateFormat,
                numberOfMonths: 1,
                onClose: function(dateText, obj) {
                    let $form = $('#'+obj.id).parents('form');

                    if ( $form.find('#plantaoTo').val().trim() == '' || $form.find('#plantaoFrom').val().trim() == '' ) {
                        $form.find('[type="submit"]').attr('disabled','disabled');
                    }

                },
                onSelect: function(dateText, obj) {

                    let $form = $('#'+obj.id).parents('form');

                    if ( $form.find('#plantaoTo').val() && $form.find('[type="submit"]').length ) {
                        $form.find('[type="submit"]').removeAttr('disabled');
                    }
                    
                }
                })
                .on( "change", function() {
                to.datepicker( "option", "minDate", getDate( this ) );
                }),
            to = $( "#plantaoTo" ).datepicker({
                defaultDate: "+1w",
                minDate: minDate,
                changeMonth: true,
                weekHeader: "W",
                maxDate: '+0m +0w',
                dateFormat: dateFormat,
                numberOfMonths: 1,
                onClose: function(dateText, obj) {
                    let $form = $('#'+obj.id).parents('form');

                    if ( $form.find('#plantaoTo').val().trim() == '' || $form.find('#plantaoFrom').val().trim() == '' ) {
                        $form.find('[type="submit"]').attr('disabled','disabled');
                    }

                },
                onSelect: function(dateText, obj) {

                    let $form = $('#'+obj.id).parents('form');

                    if ( $form.find('#plantaoFrom').val() && $form.find('[type="submit"]').length ) {
                        $form.find('[type="submit"]').removeAttr('disabled');
                    }
                    
                }
            })
            .on( "change", function() {
                from.datepicker( "option", "maxDate", getDate( this ) );
            });
        
            function getDate( element ) {
                let date;
                try {
                    date = $.datepicker.parseDate( dateFormat, element.value );
                } catch( error ) {
                    date = null;
                }

                return date;
            }

    };

    const plantoes_show_more_terms = function() {

        let x = 10;
        $('.page-nav-filter .tabs .btn-term').slice(0, 10).show().addClass('show');

        setTimeout(function() {
            if ( !$('.page-nav-filter .tabs .btn-term:not(.show)').length ) {
                $('.page-nav-filter .tabs .btn-show-more-terms').hide();
            }
        }, 500);

        $('.page-nav-filter .tabs .btn-show-more-terms').on('click', function (e) {
            e.preventDefault();
            x = x+10;
            $('.page-nav-filter .tabs .btn-term').slice(0, x).slideDown(function() {

                if ( !$('.page-nav-filter .tabs .btn-term:not(.show)').length ) {
                    $('.page-nav-filter .tabs .btn-show-more-terms').hide();
                }

            }).addClass('show');
    });

    };

    const lessons_scroll_start = function( $el ) {

        let $winH = $(window).innerHeight();

        if ( typeof mCustomScrollbar === "boolean" && $el.innerHeight() > ( $winH / 2 ) ) {
            $el.css('height','45vh');
            $el.mCustomScrollbar();
        }

    };

    const init_content_tabs = function() {

        
        $('.content-tabs > li').hide();
        if ( $('[data-comment-reply]').length ) {
            $('#tabs li:not(:last)').addClass('inactive');
            $('.content-tabs > li:last-child').show();
            $('.content-tabs .comment-form-comment textarea').focus();
        } else {
            $('#tabs li:not(:first)').addClass('inactive');
            $('.content-tabs > li:first-child').show();
        }
            
        $('#tabs li a').on('click', function(evt){
            evt.preventDefault();
            
            let t = $(this).attr('href');
        
            if( $(this).parent().hasClass('inactive') ) {
                $(this).parents('.link-tabs').find('li').addClass('inactive');           
                $(this).parent().removeClass('inactive');
                
                $('.content-tabs > li').hide();
                $(t).show();
            }
        });

        $('.content-tabs li:not(:first) .btn-toggle-content').addClass('inactive');
        $('.content-tabs > li .content').hide();
        $('.content-tabs > li:first-child .content').show();
            
        $('.content-tabs li .btn-toggle-content').on('click', function(){
            
            $btn = $(this);
            if ( $btn.hasClass('inactive') ) {
                $('.content-tabs > li .content').slideUp('fast');
                $('.content-tabs li .btn-toggle-content').addClass('inactive');
                $btn.removeClass('inactive');
                $content = $btn.parent().next();
                $content.slideDown();
            }
        
        });

    };

    const editor_text_expand = function() {

        document.querySelectorAll('.editor-text-expand').forEach(function(txt) {

            if ( window.innerWidth > 767 ) {
                $(txt).css('height', 'auto');
                $(txt).parent().find('.text-expand-toggle').hide();
            } else {

                if ( $(txt).height() > 280 ) {
                    $(txt).css( { 'height' : '270px', 'overflow' : 'hidden' } );
                    $btn = $(txt).parent().find('.text-expand-toggle');
                    $btn.css( { 'display' : 'block' } );
                    $btn.on('click', function() {
                        $btn.hide();
                        $(txt).css('height', 'auto');
                    });
                }

            }

        });

    };

    // Abre/fecha menu lateral
    const curso_toggle_menu = function() {

        document.querySelector('.curso-menu-toggle').addEventListener('click', function() {
            document.querySelector('body').classList.toggle('curso-menu-min');
        });

    };

    // Abre/fecha menu lateral mobile
    const curso_toggle_menu_mobile = function() {

        document.querySelectorAll('.btn-toggle-menu-mobile').forEach(function(btn) {
            
            btn.addEventListener('click', function() {
                document.querySelector('html').classList.toggle('menu-mobile-open');
                document.querySelector('body').classList.toggle('menu-mobile-open');
                document.documentElement.style.setProperty( '--site-body-h', window.innerHeight + 'px' );
            });

        });

    };

    // Abre/fecha menu usuário
    const toggle_user_menu = function() {

        document.querySelectorAll('.toggle-user-menu').forEach(btn => {

            btn.addEventListener('click', function() {
                document.querySelector('html').classList.toggle('user-menu-open');
                document.querySelector('body').classList.toggle('user-menu-open');
                document.documentElement.style.setProperty( '--site-body-h', window.innerHeight + 'px' );
            });
            
        });

    };

    const start_recados_player = function() {

        const audio = document.querySelector('.recardos-player-container');

        audio.addEventListener('loadedmetadata', () => {
        displayAudioDuration(audio.duration);
        });

    };

    const toggle_lessons_list = function() {

        $('.btn-toggle-lessons-list').on('click', function() {
            let $btn = $(this);

            let $lessons = $btn.parents('.course-module').find('.lessons-list');
            $btn.toggleClass('active');
            $lessons.slideToggle(
                function(){
                    lessons_scroll_start( $lessons.find('.lessons-list-scroll') );
                }
            );

        });

        if ( $('.course-lessons [data-is-current-lesson]').length ) {
            $('.course-lessons [data-is-current-lesson]').first().parents('.course-module').find('.lessons-list').slideDown(
                function(){
                    lessons_scroll_start( $('.course-lessons [data-is-current-lesson]').first().parents('.course-module').find('.lessons-list-scroll') );
                }
            );
            $('.course-lessons [data-is-current-lesson]').parents('.course-module').find('.btn-toggle-lessons-list').toggleClass('active');
            return;
        }

        if ( $('.course-lessons .next-lesson').length ) {
            $('.course-lessons .next-lesson').parents('.course-module').find('.lessons-list').slideDown();
            $('.course-lessons .next-lesson').parents('.course-module').find('.btn-toggle-lessons-list').toggleClass('active');
        } else {
            $('.course-lessons .course-module').first().find('.lessons-list').slideDown();
            $('.course-lessons .course-module').first().find('.btn-toggle-lessons-list').toggleClass('active');
        }
        
    };

    document.addEventListener('DOMContentLoaded', function() {
        init_events();
    });

})(jQuery);