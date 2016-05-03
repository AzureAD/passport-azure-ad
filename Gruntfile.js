'use strict';

module.exports = function loadGrunt(grunt) {
  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    nodeunit: {
      files: ['test/**/*_test.js'],
    },
    eslint: {
      options: {},
      gruntfile: {
        src: 'Gruntfile.js',
      },
      lib: {
        src: ['lib/**/*.js'],
      },
      examples: {
        src: ['examples/*/*.js'],
      },
      test: {
        src: ['test/**/*.js'],
      },
    },
    watch: {
      gruntfile: {
        files: '<%= eslint.gruntfile.src %>',
        tasks: ['eslint:gruntfile'],
      },
      lib: {
        files: '<%= eslint.lib.src %>',
        tasks: ['eslint:lib', 'nodeunit'],
      },
      test: {
        files: '<%= eslint.test.src %>',
        tasks: ['eslint:test', 'nodeunit'],
      },
    },
  });

  // These plugins provide necessary tasks.
  grunt.loadNpmTasks('grunt-contrib-nodeunit');
  grunt.loadNpmTasks('grunt-eslint');
  grunt.loadNpmTasks('grunt-contrib-watch');

  // Default task.
  grunt.registerTask('default', ['eslint', 'nodeunit']);
};
