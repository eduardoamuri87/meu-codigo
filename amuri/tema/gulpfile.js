var gulpconfig = require('./gulp-config.json');
var postcss = require('gulp-postcss');
var concat = require('gulp-concat');
var minify = require('gulp-minify');
var gulp = require('gulp');
var browserSync = require('browser-sync');

function css() {
    return gulp.src('./assets/css/*.css')
		.pipe(postcss())
		.on('error', function( err ) {
			console.log(err.toString());
            this.emit('end');
		})
		.pipe(gulp.dest('./public/css/'))
		.pipe(browserSync.stream());
};

gulp.task('browser-reload', function () {
	browserSync.reload();
});

gulp.task('browser-stream', function () {
	browserSync.stream();
});

function watch() {
	
}

gulp.task('watch', () => {
	gulp.watch('tailwind.config.js', gulp.parallel( css ));
	gulp.watch('assets/css/*.css', gulp.parallel( css ));
	// gulp.watch('public/css/*.css',  gulp.parallel( reload ) );
	gulp.watch('public/js/**/*.js',  gulp.parallel( reload) );
	gulp.watch('*.html',  gulp.parallel( reload) );
	gulp.watch('*.php', gulp.parallel( reload) );
	gulp.watch('*/*.php',  gulp.parallel( reload) );
});

gulp.task('build-js', () => {
	gulp.src("public/js/plugins/**/**.js")
    	.pipe(concat('plugins.js', {newLine: ';'}))
		.pipe(gulp.dest('public/js/'));
		
	gulp.src(['public/js/plugins.js'])
	  .pipe(minify())
	  .pipe(gulp.dest('public/js/'));
});

function reload(done) {
	browserSync.reload();
	done();
}

gulp.task('browser-sync', () => {
	browserSync.init({
		proxy: gulpconfig.proxyURL
	});
});

gulp.task('default', gulp.parallel( css, 'browser-sync', 'watch' ) );